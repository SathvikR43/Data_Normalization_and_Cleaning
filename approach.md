# approach.md

## Pipeline: Rules → LLM

**Rules-based processing** for structured data with clear validation standards:
- IP addresses: RFC 791 validation, octet range (0-255), leading zero normalization
- Hostnames: RFC 1123 compliance (alphanumeric + hyphens, max 63 chars)
- MAC addresses: Multi-format acceptance, normalization to aa:bb:cc:dd:ee:ff
- Site names: Abbreviation standardization (Bldg→Building, HQ, Campus)

**LLM-based processing** for unstructured text requiring context:
- Device type classification: Gemini analyzes hostname patterns and notes, returns "unknown" if insufficient evidence
- Owner parsing: Gemini distinguishes proper nouns (names) from common nouns (teams), extracts emails

**Model:** gemini-3-flash-preview  
**Temperature:** 0.1 (≤0.2 per requirements)  
**Output:** JSON format with schema enforcement

---

## Constraints

**Technical:** Python 3.7+, google-genai package, internet connection for API  
**API:** Gemini free tier ~500 requests/day  
**Data:** IPv6 detected but not normalized, /24 subnet assumption for private IPs  
**Processing:** ~10-15 seconds for 15 rows (rules: <1s, 14 LLM calls: ~7-10s)

---

## Reproduce End-to-End

```bash
# Install dependencies
pip install google-genai


export GEMINI_API_KEY="your-key"  # Mac/Linux
set GEMINI_API_KEY=your-key       # Windows

# Run pipeline
python run.py

```

**Validation:** Check anomalies.json for flagged issues, review prompts.md for LLM interactions.