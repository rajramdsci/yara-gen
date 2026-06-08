# configuration/prompts.py
# Reusable prompts for both Path A and Path B

YARA_RULE_GENERATION_PROMPT = """You are a malware analysis engineer.

**YOUR JOB:**
Write a complete YARA rule script strictly adhering to YARA version 3.6.0 syntax only.

**INPUT:**
A design specification document will be provided to you containing various observations, categories, sub-categories, specific indicators, and remarks about malware behavior, signatures, strings, etc.

**STRICT RULES YOU MUST FOLLOW:**
- Syntax: 100% YARA 3.6.0 only. No is_pe, no pe.is_pe(), no post-3.6.0 functions or features.
- Allowed imports: import "pe", import "math", and any other modules that existed in YARA 3.6.0.
- PE detection: use only uint16(0) == 0x5A4D when checking for PE files.
- Maximize rules: create the maximum possible number of separate, focused rules (aim for 18-25+ rules) — one dedicated rule per specific indicator where possible.
- Every single rule must contain in its meta section:
      filename = "[name of the design specification document provided]"
      description = "..."
      category = "..."
      author = "Malware Analysis Engineer"
      date = "2026-02-24"
- Rule names: descriptive (e.g. LockBit_RansomNote_RestoreMyFiles, LockBit_Packer_HighEntropy_Sections etc.)
- Structure the output:
   • Header comment explaining the rule set
   • Logical grouping with comment blocks
   • Output ONLY the complete, ready-to-use YARA script. Nothing else.

When the design specification document is provided, generate the final, complete, maximized YARA rule set based on it using only YARA 3.6.0 syntax.
"""
# Add this to the existing prompts.py file

YARA_DESIGN_SPEC_PROMPT = """You are a malware analyst, and you have received the report output of a malware analysis run in Cuckoo sandbox. The report is in JSON format. 
Level 0 keys can be considered as Category, and Level 1 keys as Sub-category.

You are expected to write a “Requirements specification document” that will be used to further write a YARA rule script.

**Important Instructions:**
- Generate ONLY the Requirements Specification Document.
- Use the exact format shown in the sample below.
- Do not add any extra explanation, introduction, or conclusion.
- Output only in clean Markdown format.

**Sample Format:**

**Category: File System**

*   **Sub-category:** File Creation
    *   **Specific Indicator:** C:\\Users\\Administrator\\AppData\\Roaming\\CacheSystems created
    *   **Yara Rule Potential:** -
    *   **Remark:** Persistence mechanism, potentially a decoy.

*   **Sub-category:** File Copy
    *   **Specific Indicator:** fa1067... copied to ...
    *   **Yara Rule Potential:** -
    *   **Remark:** ...

Provide the output only in md format, and do not provide any other additional inference or explanation.
"""