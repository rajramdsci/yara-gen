from src.preprocessor import process_all_reports
from src.keylevelextractor import process_all_keylevel_reports
from src.path_a_python import process_all_design_docs

def main():
    print("🚀 YARA Rule Generator Started (Python + LLM Hybrid)\n")
    
    print("=== Step 1: Key Level Extraction (Level 0 + Level 1 Keys Only) ===")
    process_all_keylevel_reports()
    
    print("\n=== Step 2: Configurable Trimming using key_details ===")
    process_all_reports()
    
    print("\n=== Step 3: Path A - Python Based YARA Requirements Design Document Generation ===")
    process_all_design_docs()
    
    print("\n✅ Full Pipeline Completed Successfully!")
    print("\nGenerated Files:")
    print("   • keylevel_*.json     → Key structure only (Level 0 + 1)")
    print("   • trim_*.json         → Content trimmed as per configuration")
    print("   • design_*.md         → YARA Requirements Design Documents (Path A)")
    
    print("\nNext Steps:")
    print("   1. Review files in design_docs/ folder")
    print("   2. Use the design documents with Grok (or other LLM) to generate final .yara rules")
    print("   3. Save generated .yara files in yara_rules/ folder")
    print("   4. Run detection tests using yara_generator.py")

if __name__ == "__main__":
    main()