import json
import os
from copy import deepcopy
from configuration.config import key_details

def get_nested_value(data, path):
    """Safely get nested value using dot notation (e.g., behavior.summary.files)"""
    keys = path.replace('->', '.').split('.')
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        elif isinstance(data, list):
            try:
                idx = int(key)
                data = data[idx] if idx < len(data) else None
            except ValueError:
                return None
        else:
            return None
    return data

def trim_report(input_path: str, output_path: str):
    """
    Trim report.json based on configuration in key_details.
    Uses deep copy for included sections.
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    trimmed = {}

    for key_config in key_details.values():
        detail = key_config['Detail']
        mode = key_config['mode']

        if '->' in detail:
            # Handle nested paths
            path = detail.split('->')[0]  # e.g., 'behavior'
            if path in report:
                if mode == 'include':
                    trimmed[path] = deepcopy(report[path])
                # For exclude, we skip copying that subtree
        else:
            # Top-level keys
            if detail in report:
                if mode == 'include':
                    trimmed[detail] = deepcopy(report[detail])
                # exclude mode: intentionally not copied

    # Special handling for CAPE->payloads->strings
    if 'CAPE' in report and key_details.get('key6', {}).get('mode') == 'include':
        cape_data = deepcopy(report['CAPE'])
        if isinstance(cape_data, list):
            for item in cape_data:
                if isinstance(item, dict) and 'strings' in item:
                    # Keep only strings in payloads
                    item['strings'] = item.get('strings', [])
        trimmed['CAPE'] = cape_data

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(trimmed, f, indent=2)

    print(f"✅ Trimmed report saved: {os.path.basename(output_path)}")
    return trimmed

def process_all_reports():
    """Pipeline function to process all JSON reports in input_reports"""
    input_dir = "input_reports"
    output_dir = "trimmed_reports"
    
    if not os.path.exists(input_dir):
        print("⚠️ input_reports folder not found!")
        return

    for filename in os.listdir(input_dir):
        if filename.endswith(".json"):
            input_path = os.path.join(input_dir, filename)
            output_filename = f"trim_{filename}"
            output_path = os.path.join(output_dir, output_filename)
            
            trim_report(input_path, output_path)