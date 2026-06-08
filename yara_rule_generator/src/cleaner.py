import os

def clear_previous_outputs():
    """
    Clears ONLY files (not sub-directories) from output folders.
    Safe for incremental runs.
    """
    print("🧹 Clearing previous output files for clean run...")

    folders_to_clear = [
        "trimmed_reports",
        "design_docs",
        "yara_rules",
        "design_docs/llmgenerated",
        "yara_rules/llmspecgen"
    ]

    for folder in folders_to_clear:
        if os.path.exists(folder):
            try:
                deleted_count = 0
                for filename in os.listdir(folder):
                    file_path = os.path.join(folder, filename)
                    if os.path.isfile(file_path):   # Only files, no sub-folders
                        os.unlink(file_path)
                        deleted_count += 1
                print(f"   ✅ Cleared {deleted_count} files from: {folder}/")
            except Exception as e:
                print(f"   ⚠️ Warning while clearing {folder}: {e}")
        else:
            os.makedirs(folder, exist_ok=True)
            print(f"   📁 Created folder: {folder}/")

    print("🧹 Cleanup completed.\n")


if __name__ == "__main__":
    clear_previous_outputs()