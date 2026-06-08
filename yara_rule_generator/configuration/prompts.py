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

# Updated Prompt for Path B (Design Spec Generation)
YARA_DESIGN_SPEC_PROMPT = """You are a malware analyst. You have received a trimmed JSON report from a Cuckoo/CAPE sandbox analysis.

**YOUR TASK:**
Create a **YARA Requirements Design Document** based on the trimmed JSON report.

**OUTPUT FORMAT REQUIREMENTS (Follow Exactly):**

- Start with this header:
  File name :{sample_name}_yara_design.pdf

  ## YARA Requirements Design Document - Path B (LLM Generated)
  Generated: [current datetime]
  Malware Sample: [sample name]
  SHA256: [sha if available, else unknown]

- Then for each relevant Category found in the JSON:
  ## Category: CATEGORY_NAME (in uppercase)

  ### Sub-category: Sub-category name

  **Yara Rule Potential:**
rule malware_{sample_short}{clean_category}{clean_subcategory} {
meta:
author = "YARA Generator - Path B"
date = "YYYY-MM-DD"
description = "Detects {sub} activity from CAPE report"
reference = "CAPE Analysis - {sample_name}"
strings:
$s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
$s2 = "TODO - Add more strings" ascii wide
condition:
uint16(0) == 0x5A4D and
filesize < 15MB and
any of them
}
text**Notes:** Brief remark about this category/sub-category.
**Relevance detection potential:** High/Medium/Low - Short explanation why it is useful.

- At the end, add:
## Overall Recommended Strategy
- Focus on categories with High relevance detection potential
- Extract real strings from CAPE.payloads, behavior.summary, static.strings etc.
- Feed this design document to Grok to generate final optimized .yara rule

**Important:**
- Only include categories that actually exist in the provided trimmed JSON.
- Do not add any extra text, explanations, or conclusions outside this structure.
- Output ONLY the markdown document.
"""