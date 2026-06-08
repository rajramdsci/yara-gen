from src.preprocessor import process_all_reports
from src.keylevelextractor import process_all_keylevel_reports
from src.path_a_python import process_all_design_docs
from src.path_a_python_yara_generator import process_all_yara_generation

def main():
    print("🚀 YARA Rule Generator Started (Python + LLM Hybrid)\n")
    
    print("=== Step 1: Key Level Extraction (Level 0 + Level 1 Keys Only) ===")
    process_all_keylevel_reports()
    
    print("\n=== Step 2: Configurable Trimming using key_details ===")
    process_all_reports()
    
    print("\n=== Step 3: Path A - Python Based YARA Requirements Design Document Generation ===")
    process_all_design_docs()
    
    print("\n=== Step 4: Path A - Generate YARA Rules (Send Design to Grok) ===")
    process_all_yara_generation()
    
    print("\n✅ Full Pipeline (Path A) Completed Successfully!")
    print("\nGenerated Files:")
    print("   • keylevel_*.json          → Key structure only")
    print("   • trim_*.json              → Trimmed content")
    print("   • Reqspec_*.md             → YARA Requirements Design Documents")
    print("   • *.yara (in yara_rules/)  → Final rules (after pasting prompt to Grok)")
    
    print("\nNext Steps:")
    print("   1. Go to each printed prompt in the console")
    print("   2. Paste it into Grok to get the .yara rule set")
    print("   3. Save the output as the suggested .yara file in yara_rules/")
    print("   4. Use yara_generator.py to test the rules against malware_samples/")

if __name__ == "__main__":
    main()