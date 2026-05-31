
# YARA Rule Generator Project

**Hybrid Python + LLM Approach for Automated YARA Rule Generation from CAPE/Cuckoo Reports**

A project to create Python code for multiple YARA requirements generation and scripts using both traditional Python and LLM-based approaches.

---

## Project Overview

This project automates the generation of high-quality YARA rules from malware analysis reports (`report.json`) produced by CAPE and Cuckoo Sandbox.

It follows a structured **two-path hybrid approach**:
- **Path A**: Traditional Python-based design document generation + LLM (Grok) for final YARA rule.
- **Path B**: Pure LLM-based (Grok) end-to-end generation.
- **Common Detection Path**: Validate generated rules against real malware samples using YARA CLI.

**Important**: No external LLM APIs are used outside of manual interaction with Grok. No `yara-python` package is required — only YARA command-line tool.

---

## Solution Flow

### 1. Inputs
- `input_reports/` → Drop all `report.json` files here (from CAPE/Cuckoo runs).
- No separate folders needed per sample.

### 2. Processing

#### Preprocessing Block
- Parses `report.json`.
- Uses `deepcopy` to extract only required keys.
- Outputs `trimmed_report.json` for clean and efficient downstream processing.

#### Path A — Traditional Python + LLM
1. Python code generates **YARA Requirement Design Document**.
2. Manually pass the design document to Grok (or any LLM) → Get final `.yara` rule.

#### Path B — Pure LLM Approach
1. Pass `trimmed_report.json` directly to Grok.
2. Grok generates **YARA Requirement Design Document**.
3. Pass the design document back to Grok → Get final `.yara` rule.

#### Common Path — Rule Validation
- Test generated `.yara` rules against malware samples.
- Use YARA CLI for detection.
- Store detailed detection logs.

---

## Folder Structure

```
yara_rule_generator/
├── setup_project.sh                 # Shell script to create folder structure
├── requirements.txt
├── README.md
├── main.py                          # Main entry point
├── .gitignore
│
├── src/
│   ├── __init__.py
│   ├── preprocessor.py              # Trimming logic
│   ├── path_a_python.py             # Python-based design doc generator
│   ├── path_b_llm.py                # LLM prompt templates
│   └── yara_generator.py            # Detection & testing module
│
├── input_reports/                   # ← Put all report.json files here
├── trimmed_reports/                 # Trimmed clean JSON outputs
├── design_docs/                     # YARA requirement design documents
├── yara_rules/                      # Final generated .yara files
├── malware_samples/                 # Manually downloaded test malware binaries
└── detection_logs/                  # Detection test result logs
```

---

## Setup Instructions

1. Clone or download the project.
2. Run the setup script:

```bash
chmod +x setup_project.sh
./setup_project.sh
```

3. Install dependencies (minimal):

```bash
pip install -r requirements.txt
```

4. Place your `report.json` files in `input_reports/`.
5. Run preprocessing:

```bash
python main.py
```

6. Follow **Path A** or **Path B** using Grok to generate rules.
7. Place test malware binaries in `malware_samples/`.
8. Run detection tests via the testing module.

---

## Key Features

- Clean preprocessing with configurable key selection.
- Dual-path flexibility (Python-first vs LLM-first).
- Command-line YARA detection with logging.
- Ready for Git version control.
- Designed for Visual Studio Code.

---

## Usage Workflow

1. **Preprocessing** → Generate `trimmed_report.json`.
2. **Path A**:
   - Run Python design generator.
   - Copy design doc → Ask Grok for `.yara` rule.
3. **Path B**:
   - Feed trimmed JSON to Grok → Get design doc → Get `.yara`.
4. **Validation**:
   - Run YARA CLI test.
   - Review logs in `detection_logs/`.

---

## Technologies

- **Python 3.8+** (standard libraries only: `json`, `copy`, `os`, `subprocess`, `datetime`)
- **YARA CLI** (must be installed on system)
- **Grok (LLM)** for rule finalization
- Shell script for project scaffolding

---

## Future Enhancements (Optional)

- Batch processing of multiple reports
- Automated string extraction in Path A
- Rich console output
- Direct Grok API integration (if needed later)





