#!/bin/bash
# ============================================
# Network Scanner - Cybersecurity Portfolio
# ============================================

TARGET="" #enter your target ip address
OUTPUT_DIR="./scan_results"
DATE=$(date +"%Y-%m-%d_%H-%M")

mkdir -p $OUTPUT_DIR

echo ""
echo ""
echo " Network Scanner Starting..."
echo " Target: $TARGET"
echo " Date:   $DATE"

echo ""
echo ""

echo "[Phase 1] Discovering live hosts..."
nmap -sn $TARGET -oN $OUTPUT_DIR/hosts_$DATE.txt
echo "Done. Results saved."

echo ""
echo ""

echo "[Phase 2] Scanning open ports..."
nmap -sV $TARGET -oN $OUTPUT_DIR/ports_$DATE.txt
echo "Done. Results saved."

echo ""
echo ""

echo "[Phase 3] OS detection (requires sudo)..."
sudo nmap -O $TARGET -oN $OUTPUT_DIR/os_$DATE.txt
echo "Done. Results saved."

echo ""
echo ""

echo " All scans complete!"
echo " Check the scan_results/ folder for output."
