#!/bin/bash
# ================================================
# YARA Rule Generator - Folder Structure + requirements.txt
# ================================================

echo "🚀 Creating minimal YARA Rule Generator Folder Structure..."

mkdir -p yara_rule_generator
cd yara_rule_generator

# Create folders
mkdir -p \
    src \
    input_reports \
    trimmed_reports \
    keylevel_reports\
    design_docs \
    yara_rules \
    malware_samples \
    detection_logs

# Create setup script itself
cat > setup_project.sh << 'EOL'
#!/bin/bash
echo "✅ Project folders already created!"
EOL
chmod +x setup_project.sh

# Create requirements.txt
cat > requirements.txt << 'EOL'
# Core dependencies for YARA Rule Generator Project
json
# No heavy packages needed - pure Python + subprocess for yara CLI
# Add more later if you extend the project
EOL

# Create placeholder files
touch README.md
touch main.py
touch .gitignore
touch src/__init__.py

echo "✅ Folder structure + requirements.txt created successfully!"
echo ""
echo "Project Structure:"
ls -la
echo ""
echo "📄 requirements.txt is ready in root folder."
echo "Next: cd yara_rule_generator && pip install -r requirements.txt"