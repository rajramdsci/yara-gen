import json
import os
from datetime import datetime
from dotenv import load_dotenv
from xai_sdk import Client
from xai_sdk.chat import system, user
from configuration.prompts import YARA_DESIGN_SPEC_PROMPT  # We'll create this next


def generate_design_spec_from_trimmed(trimmed_path: str, output_md_path: str):
    """
    Path B: Pure LLM (Grok) approach - Generate Requirements Specification Document
    """
    if not os.path.exists(trimmed_path):
        print(f"❌ Trimmed report not found: {trimmed_path}")
        return False

    with open(trimmed_path, 'r', encoding='utf-8') as f:
        trimmed_content = f.read()

    load_dotenv()

    print(f"📤 Sending trimmed report to Grok for Design Spec generation...")

    try:
        client = Client(
            api_key=os.getenv("XAI_API_KEY"),
            timeout=3600,
        )

        chat = client.chat.create(model="grok-4-1-fast-reasoning")

        chat.append(system("You are an expert malware analyst specializing in creating YARA rule design specifications from sandbox reports."))
        chat.append(user(YARA_DESIGN_SPEC_PROMPT + "\n\n**TRIMMED REPORT JSON:**\n\n" + trimmed_content))

        response = chat.sample()
        design_content = response.content

        os.makedirs(os.path.dirname(output_md_path), exist_ok=True)
        with open(output_md_path, 'w', encoding='utf-8') as f:
            f.write(design_content)

        print(f"✅ LLM Design Spec generated: {output_md_path}")
        return True

    except Exception as e:
        print(f"❌ Grok API Error: {e}")
        print("Falling back to manual mode - copy trimmed JSON and use the prompt manually.")
        return False


def process_all_path_b():
    """Process all trimmed reports using pure LLM (Path B)"""
    input_dir = "trimmed_reports"
    output_dir = "design_docs/llmgenerated"
    
    if not os.path.exists(input_dir):
        print("⚠️ trimmed_reports folder not found!")
        return

    os.makedirs(output_dir, exist_ok=True)
    count = 0

    for filename in os.listdir(input_dir):
        if filename.startswith("trim_") and filename.endswith(".json"):
            input_path = os.path.join(input_dir, filename)
            
            base_name = filename.replace("trim_", "").replace(".json", "")
            output_filename = f"Reqspec_LLM_{base_name}.md"
            output_path = os.path.join(output_dir, output_filename)
            
            if generate_design_spec_from_trimmed(input_path, output_path):
                count += 1

    print(f"\n🎉 Path B completed - Generated {count} LLM-based design documents in design_docs/llmgenerated/")


if __name__ == "__main__":
    process_all_path_b()