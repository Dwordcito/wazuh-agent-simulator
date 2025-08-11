#!/bin/bash

# Script to regenerate Wazuh folder from schema.fbs
# This is useful when you modify the FlatBuffers schema

echo "🔄 Regenerating Wazuh folder from schema.fbs..."

# Check if flatc is installed
if ! command -v flatc &> /dev/null; then
    echo "❌ Error: flatc (FlatBuffers compiler) is not installed"
    echo "   Install it with: brew install flatbuffers"
    exit 1
fi

# Check if schema.fbs exists
if [ ! -f "schema.fbs" ]; then
    echo "❌ Error: schema.fbs not found in current directory"
    exit 1
fi

# Remove existing Wazuh folder
if [ -d "Wazuh" ]; then
    echo "🗑️  Removing existing Wazuh folder..."
    rm -rf Wazuh
fi

# Generate Python code from schema
echo "🔧 Generating Python code from schema.fbs..."
flatc --python schema.fbs

# Check if generation was successful
if [ $? -eq 0 ]; then
    echo "✅ Successfully generated Wazuh folder from schema.fbs"
    echo "📁 New structure:"
    ls -la Wazuh/
    echo ""
    echo "🚀 You can now use the updated schema in your code!"
else
    echo "❌ Error generating Python code from schema.fbs"
    exit 1
fi
