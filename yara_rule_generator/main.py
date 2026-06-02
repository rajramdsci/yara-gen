from src.preprocessor import process_all_reports
from src.keylevelextractor import process_all_keylevel_reports

def main():
    print("🚀 YARA Rule Generator Started (Python + LLM Hybrid)\n")
    
    print("=== Step 1: Key Level Extraction (Level 0 + Level 1 Keys Only) ===")
    process_all_keylevel_reports()
    
    print("\n=== Step 2: Configurable Trimming using key_details ===")
    process_all_reports()
    
    print("\n✅ Full Preprocessing Pipeline Completed Successfully!")
    print("\nGenerated Files in trimmed_reports/:")
    print("   • keylevel_*.json     → Only keys/structure (Level 0 + Level 1)")
    print("   • trim_*.json         → Content trimmed as per configuration")
    
    print("\nNext Steps:")
    print("   → Review files in trimmed_reports/")
    print("   → Proceed with Path A (Python) or Path B (LLM) using Grok")

if __name__ == "__main__":
    main()