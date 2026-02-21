#!/bin/bash
# Run Ghidra headless analysis on all binaries in unanalyzed/
GHIDRA="/opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless"
PROJECT_DIR="/root/cowrie/ghidra_project"
PROJECT_NAME="cowrie_malware"
INPUT_DIR="/root/cowrie/unanalyzed"
SCRIPT_DIR="/root/cowrie/ghidra_scripts"
OUTPUT_DIR="/root/cowrie/ghidra_output"

export GHIDRA_OUTPUT_DIR="$OUTPUT_DIR"

echo "Starting Ghidra headless analysis at $(date)"
echo "Binaries to analyze: $(ls "$INPUT_DIR" | wc -l)"
echo ""

for binary in "$INPUT_DIR"/*; do
    bname=$(basename "$binary")
    echo "========================================"
    echo "Analyzing: $bname"
    echo "Started: $(date)"
    echo "========================================"

    # Run headless analysis - import, analyze, run postScript, then delete from project
    "$GHIDRA" "$PROJECT_DIR" "$PROJECT_NAME" \
        -import "$binary" \
        -overwrite \
        -postScript DecompileAnalyze.java \
        -scriptPath "$SCRIPT_DIR" \
        -deleteProject \
        2>&1 | tail -20

    echo ""
    echo "Finished $bname at $(date)"
    echo ""
done

echo "All analysis complete at $(date)"
echo "Output files:"
ls -la "$OUTPUT_DIR"
