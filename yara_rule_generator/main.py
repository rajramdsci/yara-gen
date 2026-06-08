from src.preprocessor import process_all_reports
from src.keylevelextractor import process_all_keylevel_reports
from src.path_a_python import process_all_design_docs
from src.path_a_python_yara_generator import process_all_yara_generation
from src.path_b_llm import process_all_path_b

from src.cleaner import clear_previous_outputs
from src.report_summary_generation import generate_report_summary

def main():
    print("🚀 YARA Rule Generator Started (Python + LLM Hybrid)\n")

    print(" Clear any previous outputs of run ")
    clear_previous_outputs()   # ← Call here at the beginning
    
    print("=== Step 1: Key Level Extraction (Level 0 + Level 1 Keys Only) ===")
    process_all_keylevel_reports()
    
    print("\n=== Step 2: Configurable Trimming using key_details ===")
    process_all_reports()
    
    print("\n=== Step 3: Path A - Python Based YARA Requirements Design Document Generation ===")
    process_all_design_docs()
    
    print("\n=== Step 4: Path A - Generate YARA Rules (Send Design to Grok) ===")
    # assign input dir and output dir , to ensure, python generated design documents are read and yara rules are generated in the correct location
    
    process_all_yara_generation("design_docs","yara_rules")
    
    print("\n=== Step 5: Path B - Pure LLM Design Spec Generation ===")
    # call this function to generate requirements spec documents by using trimmed json directly over a prompt to grok. 
    process_all_path_b()

    print("\n=== Step 6: Path B - Generate YARA from  LLM Design Spec  ===")
    # call this function to generate requirements spec documents by using trimmed json directly over a prompt to grok. 
    process_all_yara_generation("design_docs/llmgenerated","yara_rules/llmspecgen")

    print("\n✅ Full Pipeline (Path A) Completed Successfully!")
    print("\nGenerated Files:")
    print("   • keylevel_*.json          → Key structure only")
    print("   • trim_*.json              → Trimmed content")
    print("   • Reqspec_*.md             → YARA Requirements Design Documents")
    print("   • *.yara (in yara_rules/)  → Final rules (after pasting prompt to Grok)")
    
    print("\n=== Final Step: Generate Pipeline Summary Report ===")
    generate_report_summary()

if __name__ == "__main__":
    main()