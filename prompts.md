# prompts.md

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


#### Device Type Classification

**Row 2**
- Classification: router
- Confidence: 0.75
- Reasoning: The notes explicitly mention 'edge gw', where 'gw' is a common abbreviation for gateway, which is classified as a router. This functional description provides a stronger indicator than the generic 'host' prefix in the hostname.

**Row 6**
- Classification: unknown
- Confidence: 0.1
- Reasoning: The hostname 'local-test' is generic and does not contain standard prefixes or suffixes (like srv, sw, or rtr) to identify a specific device type. Additionally, the IP address 127.0.0.1 is a loopback address providing no context about the device's role in a network.

**Row 7**
- Classification: server
- Confidence: 0.7
- Reasoning: The hostname contains the prefix 'host', which is explicitly listed as a common pattern for servers in the provided instructions. The 'apipa' suffix refers to the Automatic Private IP Addressing range (169.254.x.x) used by the device.

**Row 9**
- Classification: unknown
- Confidence: 0.1
- Reasoning: The hostname 'badhost' is a generic placeholder and does not provide clear evidence of a specific device type. Additionally, the IP address 'abc.def.ghi.jkl' is a placeholder, and there are no descriptive notes to assist in classification.

**Row 10**
- Classification: unknown
- Confidence: 0.1
- Reasoning: The hostname 'neg' does not match any common naming conventions for network devices, and there are no notes to provide additional context.

**Row 11**
- Classification: unknown
- Confidence: 0.95
- Reasoning: The hostname 'bcast' and IP address '192.168.1.255' identify this as a network broadcast address rather than a specific hardware device type from the provided categories.

**Row 12**
- Classification: unknown
- Confidence: 0.1
- Reasoning: The IP address 192.168.1.0 and hostname 'netid' indicate this is a network identifier (subnet address) rather than a specific physical or virtual device.

**Row 15**
- Classification: unknown
- Confidence: 0.1
- Reasoning: The hostname 'missing-ip' is a generic placeholder and does not contain any keywords or patterns associated with specific network device types. No additional notes or IP information are available to assist in classification.


#### Owner Parsing

**Row 1**
- Name: priya
- Email: priya@corp.example.com
- Team: platform

**Row 2**
- Name: 
- Email: 
- Team: ops

**Row 3**
- Name: jane
- Email: jane@corp.example.com
- Team: 

**Row 4**
- Name: 
- Email: 
- Team: Facilities

**Row 5**
- Name: 
- Email: 
- Team: sec

**Row 8**
- Name: 
- Email: 
- Team: platform


**Total LLM Calls:** 14
