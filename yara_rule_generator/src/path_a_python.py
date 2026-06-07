import json
import os
import csv
from datetime import datetime

def load_master_dictionary():
    """Load master_yara_dictionary.csv"""
    csv_path = "configuration/master_yara_dictionary.csv"
    if not os.path.exists(csv_path):
        print(f"❌ Master dictionary not found at {csv_path}")
        return []
    
    master = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            master.append(row)
    print(f"✅ Loaded {len(master)} entries from master dictionary")
    return master


def generate_design_document(trimmed_path: str, output_design_path: str):
    """Generate clean YARA Requirements Design Document - Path A"""
    with open(trimmed_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    master = load_master_dictionary()

    sha = report.get("target", {}).get("file", {}).get("sha256", "unknown")[:16]
    base_name = os.path.basename(trimmed_path).replace("trim_", "").replace(".json", "")

    design_content = f"""File name :{base_name}_yara_design.pdf

## YARA Requirements Design Document - Path A (Python Generated)
Generated: {datetime.now().isoformat()}
Malware Sample: {base_name}
SHA256: {sha}

"""

    for entry in master:
        cat = entry['category']
        if cat.lower() not in [k.lower() for k in report.keys()]:
            continue

        design_content += f"\n## Category: {cat.upper()}\n"
        sub = entry['sub-category']
        design_content += f"### Sub-category: {sub}\n\n"

        clean_cat = cat.lower().replace(" ", "_")
        clean_sub = sub.lower().replace(" ", "_").replace(",", "").replace("[", "").replace("]", "")
        rule_name = f"malware_{base_name[:12]}_{clean_cat}_{clean_sub}"

        design_content += f"""**Yara Rule Potential:**
        rule {rule_name} {{
meta:
author = "YARA Generator - Path A"
date = "{datetime.now().strftime('%Y-%m-%d')}"
description = "Detects {sub} activity from CAPE report"
reference = "CAPE Analysis - {base_name}"
strings:
$s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
$s2 = "TODO - Add more strings" ascii wide
condition:
uint16(0) == 0x5A4D and
filesize < 15MB and
any of them
}}


**Notes:** {entry['Remarks']}
**Relevance detection potential:** {entry['Relevance detection potential']}
"""

    design_content += """
## Overall Recommended Strategy
- Focus on categories with High relevance detection potential
- Extract real strings from CAPE.payloads, behavior.summary, static.strings etc.
- Feed this design document to Grok to generate final optimized .yara rule
"""

    os.makedirs(os.path.dirname(output_design_path), exist_ok=True)
    
    with open(output_design_path, 'w', encoding='utf-8') as f:
        f.write(design_content)

    print(f"✅ Design Document created: {output_design_path}")
    return design_content


def process_all_design_docs():
    """Called from main.py - Processes all trimmed reports"""
    input_dir = "trimmed_reports"
    output_dir = "design_docs"
    
    if not os.path.exists(input_dir):
        print("⚠️ trimmed_reports folder not found!")
        return

    count = 0
    for filename in os.listdir(input_dir):
        if filename.startswith("trim_") and filename.endswith(".json"):
            input_path = os.path.join(input_dir, filename)
            base_name = filename.replace("trim_", "").replace(".json", "")
            output_filename = f"Reqspec_{base_name}.md"
            output_path = os.path.join(output_dir, output_filename)
            
            generate_design_document(input_path, output_path)
            count += 1
    
    print(f"\n🎉 Successfully generated {count} Reqspec_*.md files")


if __name__ == "__main__":
    process_all_design_docs()