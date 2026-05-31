from src.preprocessor import process_all_reports

def main():
    print("🚀 YARA Rule Generator Started (Python + LLM Hybrid)\n")
    
    print("Step 1: Preprocessing all reports using configuration...")
    process_all_reports()
    
    print("\n✅ Preprocessing completed successfully!")
    print("Trimmed reports are available in 'trimmed_reports/' folder.")
    print("\nNext Steps:")
    print("   • Use trimmed reports for Path A (Python) or Path B (LLM)")
    print("   • Generate design documents and .yara rules using Grok")

if __name__ == "__main__":
    main()