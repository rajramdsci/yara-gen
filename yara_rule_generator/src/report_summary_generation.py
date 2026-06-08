import os
import json
from datetime import datetime
import pandas as pd
from openpyxl import load_workbook

def count_categories_and_subcats(md_file_path: str):
    """Count categories and sub-categories in a design spec MD file"""
    if not os.path.exists(md_file_path):
        return 0, 0
    with open(md_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    categories = len([line for line in content.splitlines() if line.strip().startswith("## Category:")])
    subcats = len([line for line in content.splitlines() if line.strip().startswith("### Sub-category:")])
    return categories, subcats


def count_yara_rules(yara_file_path: str):
    """Count lines, rules, categories in a .yara file"""
    if not os.path.exists(yara_file_path):
        return 0, 0, 0, 0
    with open(yara_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    lines = len(content.splitlines())
    rules = len([line for line in content.splitlines() if line.strip().startswith("rule ")])
    cats = len([line for line in content.splitlines() if "Category:" in line])
    subcats = len([line for line in content.splitlines() if "Sub-category:" in line])
    return lines, rules, cats, subcats


def generate_report_summary():
    """Generate complete pipeline summary Excel report"""
    print("📊 Generating Pipeline Summary Report...")

    # Output folder
    output_dir = "summary_reports"
    os.makedirs(output_dir, exist_ok=True)

    data = []

    trimmed_dir = "trimmed_reports"
    design_dir = "design_docs"
    llm_design_dir = os.path.join("design_docs", "llmgenerated")
    yara_py_dir = "yara_rules"
    yara_llm_dir = os.path.join("yara_rules", "llmspecgen")

    for filename in os.listdir(trimmed_dir):
        if not filename.startswith("trim_") or not filename.endswith(".json"):
            continue

        base_name = filename.replace("trim_", "").replace(".json", "")
        input_name = filename.replace("trim_", "")

        row = {
            "File name": input_name,
            "Trimmed File output metrics": filename,
        }

        # Trimmed metrics
        trim_path = os.path.join(trimmed_dir, filename)
        with open(trim_path, 'r', encoding='utf-8') as f:
            trimmed_data = json.load(f)
        row["Record length - Total lines in trimmed output"] = len(json.dumps(trimmed_data, indent=2).splitlines())

        # Python Path A Design Spec
        py_design_file = f"Reqspec_{base_name}.md"
        py_design_path = os.path.join(design_dir, py_design_file)
        if os.path.exists(py_design_path):
            cat, sub = count_categories_and_subcats(py_design_path)
            row["Python Generated Design spec"] = py_design_file
            row["# of Category"] = cat
            row["# of sub-category"] = sub
        else:
            row["Python Generated Design spec"] = "-"
            row["# of Category"] = 0
            row["# of sub-category"] = 0

        # LLM Path B Design Spec
        llm_design_file = f"Reqspec_LLM_{base_name}.md"
        llm_design_path = os.path.join(llm_design_dir, llm_design_file)
        if os.path.exists(llm_design_path):
            cat, sub = count_categories_and_subcats(llm_design_path)
            row["LLM Generated Design spec"] = llm_design_file
            row["# of Category (LLM)"] = cat
            row["# of sub-category (LLM)"] = sub
        else:
            row["LLM Generated Design spec"] = "-"
            row["# of Category (LLM)"] = 0
            row["# of sub-category (LLM)"] = 0

        # YARA from Python Spec
        yara_py_file = f"{base_name}.yara"
        yara_py_path = os.path.join(yara_py_dir, yara_py_file)
        if os.path.exists(yara_py_path):
            lines, rules, cats, subs = count_yara_rules(yara_py_path)
            row["LLM generated Yara scripts from python spec"] = yara_py_file
            row["# of lines (Py)"] = lines
            row["# of rules (Py)"] = rules
            row["# of Category (Py YARA)"] = cats
            row["# of Sub-category (Py YARA)"] = subs
        else:
            row["LLM generated Yara scripts from python spec"] = "-"
            row["# of lines (Py)"] = 0
            row["# of rules (Py)"] = 0
            row["# of Category (Py YARA)"] = 0
            row["# of Sub-category (Py YARA)"] = 0

        # YARA from LLM Spec
        yara_llm_file = f"{base_name}.yara"
        yara_llm_path = os.path.join(yara_llm_dir, yara_llm_file)
        if os.path.exists(yara_llm_path):
            lines, rules, cats, subs = count_yara_rules(yara_llm_path)
            row["LLM Generated Yara Scripts from LLM Spec"] = yara_llm_file
            row["# of lines (LLM YARA)"] = lines
            row["# of rules (LLM YARA)"] = rules
            row["# of Category (LLM YARA)"] = cats
            row["# of Sub-category (LLM YARA)"] = subs
        else:
            row["LLM Generated Yara Scripts from LLM Spec"] = "-"
            row["# of lines (LLM YARA)"] = 0
            row["# of rules (LLM YARA)"] = 0
            row["# of Category (LLM YARA)"] = 0
            row["# of Sub-category (LLM YARA)"] = 0

        data.append(row)

    # Save Excel Report
    df = pd.DataFrame(data)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_dir, f"Report_Summary_{timestamp}.xlsx")
    
    df.to_excel(output_file, index=False)

    # Basic formatting
    wb = load_workbook(output_file)
    ws = wb.active
    for col in ws.columns:
        max_length = 0
        column = col[0].column_letter
        for cell in col:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        ws.column_dimensions[column].width = min(max_length + 2, 50)

    wb.save(output_file)
    print(f"✅ Summary Report generated successfully: {output_file}")


if __name__ == "__main__":
    generate_report_summary()