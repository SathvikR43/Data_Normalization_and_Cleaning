import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import os

# Setting up the Gemini 3(Preview)
try:
    from google import genai
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    HAS_GEMINI = True
except ImportError:
    client = None
    HAS_GEMINI = False
    print("Warning: google-genai package not installed. Install with: pip install google-genai")
    print(" LLM-based classification will be skipped. Using rules-only approach.\n")
except Exception as e:
    client = None
    HAS_GEMINI = False
    print(f"Warning: Could not configure Gemini API: {e}")
    print("Make sure GEMINI_API_KEY environment variable is set.\n")

class DataNormalizer:
    def __init__(self, input_csv: str):
        self.input_csv = input_csv
        self.anomalies = []
        self.llm_calls_log = []
        
    # ==================== IP VALIDATION (RULES ONLY) ====================
    
    def ipv4_validate_and_normalize(self, ip_str: str) -> Tuple[bool, str, str, str]:
        """Validate and normalize IPv4 addresses using deterministic rules."""
        if not ip_str or ip_str.strip().upper() in ("N/A", ""):
            return (False, ip_str, "", "missing")
        
        s = str(ip_str).strip()
        
        # Check for IPv6
        if ":" in s or "%" in s:
            return (False, s, "6", "ipv6_detected")
        
        # Split by dots
        parts = s.split(".")
        if len(parts) != 4:
            return (False, s, "", "wrong_part_count")
        
        canonical_parts = []
        for p in parts:
            if p == "":
                return (False, s, "", "empty_octet")
            
            # Check for negative
            if p.startswith("-"):
                return (False, s, "", "negative_octet")
            
            # Check for non-numeric
            if not p.isdigit():
                return (False, s, "", "non_numeric_octet")
            
            try:
                v = int(p, 10)
            except ValueError:
                return (False, s, "", "parse_error")
            
            if v < 0 or v > 255:
                return (False, s, "", "octet_out_of_range")
            
            canonical_parts.append(str(v))
        
        canonical = ".".join(canonical_parts)
        return (True, canonical, "4", "ok")
    
    def classify_ipv4_type(self, ip: str) -> str:
        """Classify IPv4 address type."""
        try:
            octets = list(map(int, ip.split(".")))
            
            if octets[0] == 10:
                return "private_rfc1918"
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return "private_rfc1918"
            if octets[0] == 192 and octets[1] == 168:
                return "private_rfc1918"
            if octets[0] == 169 and octets[1] == 254:
                return "link_local_apipa"
            if octets[0] == 127:
                return "loopback"
            
            return "public_or_other"
        except:
            return "unknown"
    
    def default_subnet(self, ip: str) -> str:
        """Generate default subnet CIDR."""
        iptype = self.classify_ipv4_type(ip)
        if iptype == "private_rfc1918":
            parts = list(map(int, ip.split(".")))
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""
    
    # ==================== HOSTNAME VALIDATION (RULES ONLY) ====================
    
    def validate_hostname(self, hostname: str) -> Tuple[bool, str]:
        """Validate hostname per RFC standards."""
        if not hostname or hostname.strip() == "":
            return (False, "missing")
        
        h = hostname.strip()
        
        # RFC 1123: alphanumeric and hyphens, start with alphanumeric
        # Max 63 chars per label, 253 total
        if len(h) > 253:
            return (False, "too_long")
        
        # Check valid characters
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if not re.match(pattern, h):
            return (False, "invalid_format")
        
        return (True, "ok")
    
    def validate_fqdn(self, fqdn: str) -> Tuple[bool, str]:
        """Validate FQDN."""
        if not fqdn or fqdn.strip() == "":
            return (False, "missing")
        
        f = fqdn.strip()
        
        # Must have at least one dot
        if "." not in f:
            return (False, "missing_domain")
        
        labels = f.split(".")
        for label in labels:
            if len(label) > 63 or len(label) == 0:
                return (False, "invalid_label_length")
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', label):
                return (False, "invalid_label_format")
        
        return (True, "ok")
    
    def check_fqdn_consistency(self, hostname: str, fqdn: str) -> bool:
        """Check if FQDN starts with hostname."""
        if not hostname or not fqdn:
            return False
        return fqdn.lower().startswith(hostname.lower() + ".")
    
    def generate_reverse_ptr(self, ip: str, ip_valid: bool) -> str:
        """Generate reverse PTR record."""
        if not ip_valid:
            return ""
        try:
            octets = ip.split(".")
            return f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        except:
            return ""
    
    # ==================== MAC ADDRESS VALIDATION (RULES ONLY) ====================
    
    def normalize_mac(self, mac: str) -> Tuple[bool, str, str]:
        """Normalize MAC address to standard format."""
        if not mac or mac.strip() == "":
            return (False, "", "missing")
        
        m = mac.strip()
        
        # Remove common separators
        cleaned = re.sub(r'[-:.]', '', m)
        
        # Check if valid hex and correct length
        if not re.match(r'^[0-9A-Fa-f]{12}$', cleaned):
            return (False, m, "invalid_format")
        
        # Normalize to colon-separated lowercase
        normalized = ":".join([cleaned[i:i+2].lower() for i in range(0, 12, 2)])
        return (True, normalized, "ok")
    
    # ==================== OWNER PARSING (LLM-BASED) ====================
    
    def parse_owner_llm(self, owner: str, row_id: str) -> Tuple[str, str, str]:
        """Parse owner field using LLM for complex/ambiguous cases."""
        if not owner or owner.strip() == "":
            return ("", "", "")
        
        o = owner.strip()
        
        # Use LLM for all owner parsing if available
        if HAS_GEMINI:
            print(f"    Row {row_id}: Attempting LLM owner parsing...", end="", flush=True)
            try:
                prompt = f"""Parse the owner information from this text into structured fields.

Owner text: "{o}"

IMPORTANT INSTRUCTIONS:
1. If the text is a PROPER NOUN (person's name like "John", "Priya", "Jane"), put it in "name"
2. If the text is a COMMON NOUN (team/department like "ops", "platform", "security", "facilities"), put it in "team"
3. Extract any email addresses found
4. A team in parentheses like "(engineering)" goes in "team"

Examples:

Input: "priya (platform) priya@corp.example.com"
Output: {{"name": "priya", "email": "priya@corp.example.com", "team": "platform"}}
(Person name + team + email)

Input: "ops"
Output: {{"name": "", "email": "", "team": "ops"}}
(Common noun = team, not a person name)

Input: "platform"
Output: {{"name": "", "email": "", "team": "platform"}}
(Common noun = team, not a person name)

Input: "Facilities"
Output: {{"name": "", "email": "", "team": "Facilities"}}
(Department/team, not a person)

Input: "jane@corp.example.com"
Output: {{"name": "jane", "email": "jane@corp.example.com", "team": ""}}
(Email provides the name)

Input: "sec"
Output: {{"name": "", "email": "", "team": "sec"}}
(Short for security team)

Extract and return:
- name: Person's name (empty string if the text is a team/department)
- email: Email address (empty string if not present)
- team: Team/department name (empty string if the text is a person's name)

Respond ONLY with valid JSON, no additional text."""

                response = client.models.generate_content(
                    model='gemini-3-flash-preview',
                    contents=prompt,
                    config={
                        'temperature': 0.1,
                        'response_mime_type': 'application/json'
                    }
                )
                
                result = json.loads(response.text)
                
                name = result.get("name", "")
                email = result.get("email", "")
                team = result.get("team", "")
                
                print(f" ✓")
                
                self.llm_calls_log.append({
                    "purpose": "owner_parsing",
                    "prompt": prompt,
                    "response": response.text,
                    "parsed_name": name,
                    "parsed_email": email,
                    "parsed_team": team,
                    "source_row_id": row_id
                })
                
                return (name, email, team)
                
            except Exception as e:
                print(f" ✗ Failed: {str(e)[:50]}...")
                print(f"       Falling back to regex for row {row_id}")
                # Fall through to regex fallback below
        
        # Fallback ONLY if LLM not available or failed
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', o)
        team_match = re.search(r'\(([^)]+)\)', o)
        
        email = email_match.group(0) if email_match else ""
        team = team_match.group(1).strip() if team_match else ""
        name = o
        if email:
            name = name.replace(email, "").strip()
        if team_match:
            name = name.replace(team_match.group(0), "").strip()
        name = name.strip().strip(",").strip()
        
        return (name, email, team)
    
    # ==================== SITE NORMALIZATION (RULES ONLY) ====================
    
    def normalize_site(self, site: str) -> str:
        """Normalize site names using rules for consistency."""
        if not site or site.strip().upper() in ("N/A", ""):
            return ""
        
        s = site.strip()
        
        # First, normalize separators (convert hyphens/underscores to spaces for processing)
        s = re.sub(r'[-_]+', ' ', s)
        
        # Normalize multiple spaces to single
        s = re.sub(r'\s+', ' ', s)
        
        # Normalize common abbreviations (case-insensitive)
        s = re.sub(r'\b(bldg|building)\b', 'Building', s, flags=re.IGNORECASE)
        s = re.sub(r'\b(campus)\b', 'Campus', s, flags=re.IGNORECASE)
        s = re.sub(r'\b(hq)\b', 'HQ', s, flags=re.IGNORECASE)
        s = re.sub(r'\b(lab)\b', 'Lab', s, flags=re.IGNORECASE)
        s = re.sub(r'\b(dc)\b', 'DC', s, flags=re.IGNORECASE)
        
        # Standardize spacing around numbers (e.g., "Building1" -> "Building 1")
        s = re.sub(r'([a-zA-Z])(\d)', r'\1 \2', s)
        
        # Final cleanup: remove extra spaces
        s = re.sub(r'\s+', ' ', s).strip()
        
        return s
    
    # ==================== DEVICE TYPE CLASSIFICATION (LLM-BASED) ====================
    
    def classify_device_type_llm(self, row_data: Dict[str, str]) -> Tuple[str, str]:
        """Classify device type using LLM for all ambiguous cases."""
        
        device_type = row_data.get("device_type", "").strip().lower()
        hostname = row_data.get("hostname", "").strip()
        notes = row_data.get("notes", "").strip()
        ip_addr = row_data.get("ip", "").strip()
        
        # If device_type is explicitly provided and valid, use it (high confidence)
        known_types = ["server", "router", "switch", "printer", "iot", "firewall", "access point", "workstation"]
        if device_type in known_types:
            return (device_type, "high")
        
        # For everything else (empty or unknown device_type), use LLM if available
        if HAS_GEMINI:
            print(f"    Row {row_data.get('source_row_id')}: Attempting LLM device classification...", end="", flush=True)
            try:
                prompt = f"""Classify this network device type based on the information provided.

Hostname: {hostname if hostname else 'N/A'}
Notes: {notes if notes else 'N/A'}
IP Address: {ip_addr if ip_addr else 'N/A'}

IMPORTANT INSTRUCTIONS:
- Analyze the hostname patterns and notes carefully
- If there is clear evidence (hostname contains srv, sw, rtr, etc. OR notes describe the device), classify it
- If there is NO clear supporting information to determine the device type, respond with "unknown"
- Do NOT guess if the information is insufficient

Common patterns to look for:
- Servers: srv, host, db, web, app, sql
- Routers: rtr, router, gw, gateway, edge
- Switches: sw, switch, core
- Printers: print, printer
- IoT devices: cam, camera, iot, sensor
- Access Points: ap, wireless, wifi
- Firewalls: fw, firewall

Respond with a JSON object:
{{"device_type": "server", "confidence": 0.85, "reasoning": "Brief explanation of why you chose this classification"}}

Valid device types: server, router, switch, printer, iot, firewall, access point, workstation, unknown

If uncertain or no clear indicators exist, use device_type: "unknown" with low confidence."""

                response = client.models.generate_content(
                    model='gemini-3-flash-preview',
                    contents=prompt,
                    config={
                        'temperature': 0.1,
                        'response_mime_type': 'application/json'
                    }
                )
                
                result = json.loads(response.text)
                
                classification = result.get("device_type", "unknown").lower()
                confidence_score = result.get("confidence", 0.0)
                reasoning = result.get("reasoning", "")
                
                print(f" ✓ {classification}")
                
                self.llm_calls_log.append({
                    "purpose": "device_type_classification",
                    "prompt": prompt,
                    "response": response.text,
                    "classification": classification,
                    "confidence": confidence_score,
                    "reasoning": reasoning,
                    "source_row_id": row_data.get("source_row_id")
                })
                
                # Confidence level based on LLM score
                if confidence_score >= 0.8:
                    conf_level = "medium"
                else:
                    conf_level = "low"
                
                return (classification, conf_level)
                
            except Exception as e:
                print(f" ✗ Failed: {str(e)[:50]}...")
                print(f"       API error for row {row_data.get('source_row_id')}, using fallback")
            
                pass
        
    
        # This should only run if API is properly configured
        clues = (hostname + " " + notes).lower()
        
        if any(x in clues for x in ["srv", "server", "db", "host", "sql", "web", "app"]):
            return ("server", "medium")
        if any(x in clues for x in ["rtr", "router", "gw", "gateway", "edge"]):
            return ("router", "medium")
        if any(x in clues for x in ["sw", "switch", "core"]):
            return ("switch", "medium")
        if any(x in clues for x in ["print", "printer"]):
            return ("printer", "medium")
        if any(x in clues for x in ["cam", "camera", "iot", "sensor"]):
            return ("iot", "medium")
        if any(x in clues for x in ["ap", "access", "wireless", "wifi"]):
            return ("access point", "medium")
        if any(x in clues for x in ["fw", "firewall"]):
            return ("firewall", "medium")
        if any(x in clues for x in ["pc", "laptop", "desktop", "workstation"]):
            return ("workstation", "medium")
        
        return ("unknown", "low")
    
    # ==================== MAIN PROCESSING ====================
    
    def process(self):
        """Main processing pipeline."""
        output_rows = []
        
        with open(self.input_csv, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                row_id = row.get("source_row_id", "")
                steps = []
                row_anomalies = []
                
                # 1. IP Validation (RULES ONLY)
                raw_ip = row.get("ip", "")
                ip_valid, ip_normalized, ip_version, ip_reason = self.ipv4_validate_and_normalize(raw_ip)
                steps.append("ip_trim")
                
                if ip_valid:
                    steps.append("ip_parse")
                    steps.append("ip_normalize")
                    subnet_cidr = self.default_subnet(ip_normalized)
                    reverse_ptr = self.generate_reverse_ptr(ip_normalized, True)
                else:
                    steps.append(f"ip_invalid_{ip_reason}")
                    subnet_cidr = ""
                    reverse_ptr = ""
                    row_anomalies.append({
                        "field": "ip",
                        "type": ip_reason,
                        "value": raw_ip
                    })
                
                # 2. Hostname Validation (RULES ONLY)
                raw_hostname = row.get("hostname", "")
                hostname_valid, hostname_reason = self.validate_hostname(raw_hostname)
                steps.append("hostname_trim")
                
                if hostname_valid:
                    steps.append("hostname_validate")
                    hostname_out = raw_hostname.strip()
                else:
                    steps.append(f"hostname_invalid_{hostname_reason}")
                    hostname_out = raw_hostname.strip()
                    if raw_hostname.strip():
                        row_anomalies.append({
                            "field": "hostname",
                            "type": hostname_reason,
                            "value": raw_hostname
                        })
                
                # 3. FQDN Validation (RULES ONLY)
                raw_fqdn = row.get("fqdn", "")
                fqdn_valid, fqdn_reason = self.validate_fqdn(raw_fqdn)
                steps.append("fqdn_trim")
                
                if fqdn_valid:
                    steps.append("fqdn_validate")
                    fqdn_out = raw_fqdn.strip()
                    fqdn_consistent = self.check_fqdn_consistency(hostname_out, fqdn_out)
                else:
                    fqdn_out = raw_fqdn.strip()
                    fqdn_consistent = False
                    if raw_fqdn.strip():
                        row_anomalies.append({
                            "field": "fqdn",
                            "type": fqdn_reason,
                            "value": raw_fqdn
                        })
                
                # 4. MAC Address Validation (RULES ONLY)
                raw_mac = row.get("mac", "")
                mac_valid, mac_normalized, mac_reason = self.normalize_mac(raw_mac)
                steps.append("mac_trim")
                
                if mac_valid:
                    steps.append("mac_normalize")
                    mac_out = mac_normalized
                else:
                    mac_out = raw_mac.strip()
                    if raw_mac.strip():
                        steps.append(f"mac_invalid_{mac_reason}")
                        row_anomalies.append({
                            "field": "mac",
                            "type": mac_reason,
                            "value": raw_mac
                        })
                
                # 5. Owner Parsing (LLM-BASED)
                raw_owner = row.get("owner", "")
                owner_name, owner_email, owner_team = self.parse_owner_llm(raw_owner, row_id)
                steps.append("owner_parse_llm")
                
                # 6. Device Type Classification (LLM-BASED)
                device_type, device_confidence = self.classify_device_type_llm(row)
                steps.append(f"device_classify_llm_{device_confidence}")
                
                # 7. Site Normalization (RULES ONLY)
                raw_site = row.get("site", "")
                site_normalized = self.normalize_site(raw_site)
                steps.append("site_normalize")
                
                # Build output row
                output_row = {
                    "ip": ip_normalized if ip_valid else raw_ip.strip(),
                    "ip_valid": "true" if ip_valid else "false",
                    "ip_version": ip_version,
                    "subnet_cidr": subnet_cidr,
                    "hostname": hostname_out,
                    "hostname_valid": "true" if hostname_valid else "false",
                    "fqdn": fqdn_out,
                    "fqdn_consistent": "true" if fqdn_consistent else "false",
                    "reverse_ptr": reverse_ptr,
                    "mac": mac_out,
                    "mac_valid": "true" if mac_valid else "false",
                    "owner": owner_name,
                    "owner_email": owner_email,
                    "owner_team": owner_team,
                    "device_type": device_type,
                    "device_type_confidence": device_confidence,
                    "site": raw_site.strip(),  # Keep original site value
                    "site_normalized": site_normalized,  # Normalized version
                    "source_row_id": row_id,
                    "normalization_steps": "|".join(steps)
                }
                
                output_rows.append(output_row)
                
                # Add to anomalies if any issues found
                if row_anomalies:
                    self.anomalies.append({
                        "source_row_id": row_id,
                        "issues": row_anomalies,
                        "recommended_actions": self.generate_recommendations(row_anomalies)
                    })
        
        return output_rows
    
    def generate_recommendations(self, issues: List[Dict]) -> List[str]:
        """Generate recommendations for anomalies."""
        recommendations = []
        
        for issue in issues:
            field = issue["field"]
            issue_type = issue["type"]
            
            if field == "ip":
                if "out_of_range" in issue_type:
                    recommendations.append("Correct IP octets to valid range (0-255)")
                elif "wrong_part_count" in issue_type:
                    recommendations.append("Verify IP address has exactly 4 octets")
                elif "ipv6" in issue_type:
                    recommendations.append("Use IPv4 address or update schema to support IPv6")
                else:
                    recommendations.append("Correct or validate IP address format")
            
            elif field == "hostname":
                recommendations.append("Update hostname to meet RFC 1123 standards")
            
            elif field == "mac":
                recommendations.append("Correct MAC address to valid 12-digit hex format")
            
            elif field == "fqdn":
                recommendations.append("Ensure FQDN has valid domain structure")
        
        return recommendations if recommendations else ["Review and correct field data"]
    
    def save_outputs(self, output_rows: List[Dict]):
        """Save all output files."""
        
        try:
            # 1. Save inventory_clean.csv
            print("  Creating inventory_clean.csv...", end="", flush=True)
            with open("inventory_clean.csv", "w", newline="", encoding="utf-8") as f:
                fieldnames = [
                    "ip", "ip_valid", "ip_version", "subnet_cidr",
                    "hostname", "hostname_valid", "fqdn", "fqdn_consistent", "reverse_ptr",
                    "mac", "mac_valid",
                    "owner", "owner_email", "owner_team",
                    "device_type", "device_type_confidence",
                    "site", "site_normalized",
                    "source_row_id", "normalization_steps"
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(output_rows)
            print(" ✓")
            
            # 2. Save anomalies.json
            print("  Creating anomalies.json...", end="", flush=True)
            with open("anomalies.json", "w", encoding="utf-8") as f:
                json.dump(self.anomalies, f, indent=2)
            print(" ✓")
            
            # 3. Save prompts.md
            print("  Creating prompts.md...", end="", flush=True)
            self.create_prompts_md()
            print(" ✓")
            
        except Exception as e:
            print(f"\n\n❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def create_prompts_md(self):
        """Document all LLM prompts used."""
        content = """# prompts.md

## LLM Interaction Log

This document details every LLM call made during the data normalization process using Google Gemini API.

**LLM Usage Strategy:** This pipeline uses LLM ONLY for two specific tasks:
1. **Device type classification** (when device_type field is empty/ambiguous)
2. **Owner information parsing** (for all owner fields)

All other fields (IP, hostname, FQDN, MAC, site) use deterministic rules only.

---

### 1. Device Type Classification

**Purpose:** Classify device types using contextual understanding of hostname patterns, notes, and IP addressing.

**Model:** Gemini 3 Flash Preview (gemini-3-flash-preview)  
**Temperature:** 0.1 (≤0.2 per assignment requirements)  
**Output Format:** JSON

**Trigger:** Device_type field is empty or not in known types

**Prompt:**
```
Classify this network device type based on the information provided.

Hostname: {hostname}
Notes: {notes}
IP Address: {ip}

IMPORTANT INSTRUCTIONS:
- Analyze the hostname patterns and notes carefully
- If there is clear evidence (hostname contains srv, sw, rtr, etc. OR notes describe the device), classify it
- If there is NO clear supporting information to determine the device type, respond with "unknown"
- Do NOT guess if the information is insufficient

Common patterns to look for:
- Servers: srv, host, db, web, app, sql
- Routers: rtr, router, gw, gateway, edge
- Switches: sw, switch, core
- Printers: print, printer
- IoT devices: cam, camera, iot, sensor
- Access Points: ap, wireless, wifi
- Firewalls: fw, firewall

Respond with a JSON object:
{"device_type": "server", "confidence": 0.85, "reasoning": "Brief explanation of why you chose this classification"}

Valid device types: server, router, switch, printer, iot, firewall, access point, workstation, unknown

If uncertain or no clear indicators exist, use device_type: "unknown" with low confidence.
```

**Rationale:** Device classification benefits from understanding context and naming conventions. The LLM is instructed to return "unknown" when there's insufficient information rather than guessing. This ensures that ambiguous devices are properly flagged for manual review. Low temperature (0.1) ensures deterministic outputs.

---

### 2. Owner Information Parsing

**Purpose:** Extract structured owner information from unstructured text.

**Model:** Gemini 3 Flash Preview (gemini-3-flash-preview)  
**Temperature:** 0.1  
**Output Format:** JSON

**Trigger:** Owner field is not empty

**Prompt:**
```
Parse the owner information from this text into structured fields.

Owner text: "{text}"

IMPORTANT INSTRUCTIONS:
1. If the text is a PROPER NOUN (person's name like "John", "Priya", "Jane"), put it in "name"
2. If the text is a COMMON NOUN (team/department like "ops", "platform", "security", "facilities"), put it in "team"
3. Extract any email addresses found
4. A team in parentheses like "(engineering)" goes in "team"

Examples:

Input: "priya (platform) priya@corp.example.com"
Output: {"name": "priya", "email": "priya@corp.example.com", "team": "platform"}

Input: "ops"
Output: {"name": "", "email": "", "team": "ops"}
(Common noun = team, not a person name)

Input: "platform"
Output: {"name": "", "email": "", "team": "platform"}

Input: "Facilities"
Output: {"name": "", "email": "", "team": "Facilities"}

Input: "jane@corp.example.com"
Output: {"name": "jane", "email": "jane@corp.example.com", "team": ""}

Input: "sec"
Output: {"name": "", "email": "", "team": "sec"}

Extract:
- name: Person's name (empty if the text is a team/department)
- email: Email address (empty if not present)
- team: Team/department name (empty if the text is a person's name)

Respond ONLY with valid JSON.
```

**Rationale:** Owner fields require intelligent parsing to distinguish between person names (proper nouns) and team names (common nouns). For example, "ops" should be recognized as a team (operations), while "priya" should be recognized as a person's name. The LLM's natural language understanding can make this distinction better than regex patterns.

---

### LLM Calls Made

"""
        
        if self.llm_calls_log:
            device_calls = [c for c in self.llm_calls_log if c['purpose'] == 'device_type_classification']
            owner_calls = [c for c in self.llm_calls_log if c['purpose'] == 'owner_parsing']
            
            if device_calls:
                content += "\n#### Device Type Classification\n\n"
                for i, call in enumerate(device_calls, 1):
                    content += f"**Row {call['source_row_id']}**\n"
                    content += f"- Classification: {call['classification']}\n"
                    content += f"- Confidence: {call['confidence']}\n"
                    content += f"- Reasoning: {call['reasoning']}\n\n"
            
            if owner_calls:
                content += "\n#### Owner Parsing\n\n"
                for i, call in enumerate(owner_calls, 1):
                    content += f"**Row {call['source_row_id']}**\n"
                    content += f"- Name: {call['parsed_name']}\n"
                    content += f"- Email: {call['parsed_email']}\n"
                    content += f"- Team: {call['parsed_team']}\n\n"
            
            content += f"\n**Total LLM Calls:** {len(self.llm_calls_log)}\n"
        else:
            content += "\n*No LLM calls were made.*\n"
        
        with open("prompts.md", "w", encoding="utf-8") as f:
            f.write(content)


def main():
    input_csv = "inventory_raw.csv"
    
    print("=" * 60)
    print("INFOBLOX DATA NORMALIZATION PIPELINE")
    print("=" * 60)
    print()
    
    if HAS_GEMINI:
        print("✓ Google Gemini API available (using gemini-3-flash-preview)")
        print("  LLM enabled for: device_type and owner")
    else:
        print("  Gemini API not available (rules-only fallback)")
    
    print()
    print("Starting data normalization process...")
    print(f"Input: {input_csv}")
    print()
    
    normalizer = DataNormalizer(input_csv)
    
    print("Processing rows with rules and LLM...")
    output_rows = normalizer.process()
    print(f"✓ Processed {len(output_rows)} rows")
    print()
    
    print("Generating outputs...")
    normalizer.save_outputs(output_rows)
    print()
    
    print("=" * 60)
    print("COMPLETE")
    print("=" * 60)
    print()
    print(f"Anomalies detected: {len(normalizer.anomalies)}")
    print(f"LLM calls made: {len(normalizer.llm_calls_log)}")
    if normalizer.llm_calls_log:
        device_calls = len([c for c in normalizer.llm_calls_log if c['purpose'] == 'device_type_classification'])
        owner_calls = len([c for c in normalizer.llm_calls_log if c['purpose'] == 'owner_parsing'])
        print(f"  - Device type: {device_calls}")
        print(f"  - Owner parsing: {owner_calls}")
    print()
    print("Check prompts.md for LLM interaction details!")
    print()


if __name__ == "__main__":
    main()