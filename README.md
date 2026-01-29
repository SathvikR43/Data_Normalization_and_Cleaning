# Network-Inventory-Records-Data-Cleaning

## Overview

This pipeline cleans and normalizes network inventory data for IPAM/DNS/DHCP workflows. It uses deterministic rules for structured data validation (IP addresses, MAC addresses) and Google Gemini LLM for unstructured text parsing (device type classification, owner information).

---

## Setup


### Set API Key

**Windows (Command Prompt):**
```bash
set GEMINI_API_KEY=your-key-here
```

**Windows (PowerShell):**
```bash
$env:GEMINI_API_KEY="your-key-here"
```

**Mac/Linux:**
```bash
export GEMINI_API_KEY="your-key-here"
```

---

## Running the Pipeline

```bash
python run.py
```

---

## Outputs

The script generates 3 files:

1. **inventory_clean.csv** - Normalized data with 20 columns matching target schema
2. **anomalies.json** - Detected data quality issues with recommendations
3. **prompts.md** - Complete log of all LLM interactions

---

## What Gets Processed

**Rules-based validation:**
- IP addresses (RFC 791 compliance)
- Hostnames (RFC 1123 compliance)
- MAC addresses (multi-format normalization)
- FQDN validation
- Site name standardization

**LLM-based processing:**
- Device type classification (temperature: 0.1)
- Owner information parsing (distinguishes names from teams)

**Model:** gemini-3-flash-preview  
**LLM Calls Expected:** ~14 (8 device classifications + 6 owner parsing)

---

## Deliverables

- `run.py` - Main pipeline script
- `inventory_raw.csv` - Input test data
- `inventory_clean.csv` - Generated output
- `anomalies.json` - Generated anomaly report
- `prompts.md` - Generated LLM log
- `approach.md` - Pipeline documentation
- `cons.md` - Limitations analysis
- `ddi_ideas.md` - Integration concepts (optional)

---

## Requirements

- Python 3.7+
- google-genai package
- Internet connection (for Gemini API)
- API key from Google AI Studio

---

## Processing Time

- Deterministic rules: <1 second
- LLM calls: ~7-10 seconds (14 requests)
- Total: ~10-15 seconds

---

## Anomalies Detected

The pipeline detected 7 data quality issues in the test dataset:
- Invalid IP formats (out of range, wrong octet count, negative values)
- IPv6 addresses (detected but not fully normalized)
- Missing IP addresses

All anomalies include specific issue types and recommended corrective actions.

---

## Author

Sathvik  
Data Analytics Engineering Graduate, Northeastern University 
