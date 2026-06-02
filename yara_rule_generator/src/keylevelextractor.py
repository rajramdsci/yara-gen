import json
import os

def extract_key_levels(input_path: str, output_path: str):
    """
    Extracts only Level 0 (top-level keys) and Level 1 (immediate child keys)
    from report.json. Only keys/structure is kept, values are discarded.
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    key_structure = {}

    # Level 0: Top-level keys
    for key0, value in report.items():
        key_structure[key0] = {}

        # Level 1: Immediate children
        if isinstance(value, dict):
            for key1 in value.keys():
                key_structure[key0][key1] = {}   # Empty to show structure only
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                # Show structure of first item as sample
                key_structure[key0] = {"[0]": {k: {} for k in value[0].keys()}}
            else:
                key_structure[key0] = {"[list]": []}
        else:
            key_structure[key0] = "scalar"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(key_structure, f, indent=2)

    print(f"✅ Key Level Structure extracted: {os.path.basename(output_path)}")
    return key_structure


def process_all_keylevel_reports():
    """Process all reports in input_reports folder"""
    input_dir = "input_reports"
    output_dir = "keylevel_reports"
    
    if not os.path.exists(input_dir):
        print("⚠️ input_reports folder not found!")
        return

    for filename in os.listdir(input_dir):
        if filename.endswith(".json"):
            input_path = os.path.join(input_dir, filename)
            output_filename = f"keylevel_{filename}"
            output_path = os.path.join(output_dir, output_filename)
            
            extract_key_levels(input_path, output_path)