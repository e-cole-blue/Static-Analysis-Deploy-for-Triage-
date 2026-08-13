#!/usr/bin/env bash
set -Eeuo pipefail

# maldoc_static.sh
# Usage:
#   chmod +x maldoc_static.sh
#   ./maldoc_static.sh /path/to/suspicious.xls

TARGET="${1:-}"

if [[ -z "$TARGET" || ! -f "$TARGET" ]]; then
  echo "Usage: $0 /path/to/suspicious.doc/.docm/.xls/.xlsm/.xlsx"
  exit 1
fi

TARGET="$(realpath "$TARGET")"
BASE="$(basename "$TARGET")"
STAMP="$(date +'%Y%m%d_%H%M%S')"
TOOLS="$HOME/maldoc-tools"
OUT="$PWD/maldoc_analysis_${BASE}_${STAMP}"

mkdir -p "$TOOLS" "$OUT"

echo "[+] Target: $TARGET"
echo "[+] Output: $OUT"

echo "[+] Installing Ubuntu packages..."
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git python3 python3-venv python3-pip \
  binutils file p7zip-full unzip yara exiftool ripgrep coreutils

echo "[+] Setting up Python venv..."
python3 -m venv "$TOOLS/venv"
source "$TOOLS/venv/bin/activate"
python -m pip install --upgrade pip setuptools wheel

echo "[+] Installing maldoc tools..."
python -m pip install -U oletools olefile msoffcrypto-tool yara-python

# Optional but useful for Excel 4.0 / XLM macro analysis
python -m pip install -U "git+https://github.com/DissectMalware/XLMMacroDeobfuscator.git" || true

echo "[+] Pulling Didier Stevens Suite..."
if [[ ! -d "$TOOLS/DidierStevensSuite/.git" ]]; then
  git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite.git "$TOOLS/DidierStevensSuite"
else
  git -C "$TOOLS/DidierStevensSuite" pull --ff-only || true
fi

run_tool() {
  local outfile="$1"
  shift
  echo "[+] Running: $*"
  {
    echo "$ $*"
    echo
    "$@"
  } > "$OUT/$outfile" 2>&1 || {
    echo "[!] Command failed: $*" >> "$OUT/$outfile"
  }
}

echo "[+] Basic file info..."
{
  echo "Target: $TARGET"
  echo "Filename: $BASE"
  echo "Analysis Time: $(date)"
  echo
  echo "SHA256:"
  sha256sum "$TARGET"
  echo
  echo "SHA1:"
  sha1sum "$TARGET"
  echo
  echo "MD5:"
  md5sum "$TARGET"
  echo
  echo "File Type:"
  file "$TARGET"
} > "$OUT/00_hashes_filetype.txt"

run_tool "01_exiftool_metadata.txt" exiftool "$TARGET"

echo "[+] Extracting ASCII and UTF-16LE strings..."
strings -a -n 6 "$TARGET" > "$OUT/02_strings_ascii.txt" || true
strings -a -el -n 6 "$TARGET" > "$OUT/03_strings_utf16le.txt" || true

cat "$OUT/02_strings_ascii.txt" "$OUT/03_strings_utf16le.txt" \
  | sort -u > "$OUT/04_strings_combined_unique.txt"

echo "[+] Pulling common IOCs from strings..."
grep -Eai \
  '(https?://|hxxps?://|www\.|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|([0-9]{1,3}\.){3}[0-9]{1,3}|[a-z0-9.-]+\.(com|net|org|ru|cn|top|xyz|info|biz|io|co|us|uk|site|online|click|work|shop))' \
  "$OUT/04_strings_combined_unique.txt" \
  > "$OUT/05_iocs_raw.txt" || true

echo "[+] Pulling suspicious command/macro strings..."
grep -Eai \
  '(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|Invoke-|IEX|FromBase64String|base64|CreateObject|WScript\.Shell|Shell\.Application|WinHttpRequest|XMLHTTP|URLDownloadToFile|AutoOpen|Auto_Open|Document_Open|Workbook_Open|Workbook_Activate|DDE|DDEAUTO|Shell\(|Environ|Chr|ChrW|StrReverse|ExecuteExcel4Macro|FORMULA|CALL\(|REGISTER\()' \
  "$OUT/04_strings_combined_unique.txt" \
  > "$OUT/06_suspicious_strings.txt" || true

echo "[+] Creating basic YARA rule..."
cat > "$OUT/basic_maldoc_triage.yar" <<'YARA'
rule Basic_Suspicious_Maldoc_Static_Strings
{
    meta:
        description = "Basic static triage strings for suspicious Office documents"
        author = "local triage"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Auto_Open" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "Workbook_Open" nocase
        $p1 = "powershell" nocase
        $p2 = "cmd.exe" nocase
        $p3 = "mshta" nocase
        $p4 = "rundll32" nocase
        $p5 = "regsvr32" nocase
        $p6 = "certutil" nocase
        $p7 = "bitsadmin" nocase
        $o1 = "CreateObject" nocase
        $o2 = "WScript.Shell" nocase
        $o3 = "XMLHTTP" nocase
        $o4 = "WinHttpRequest" nocase
        $e1 = "ExecuteExcel4Macro" nocase
        $e2 = "FORMULA" nocase
        $e3 = "REGISTER(" nocase
        $e4 = "CALL(" nocase
        $b1 = "FromBase64String" nocase
        $b2 = "StrReverse" nocase
        $b3 = "ChrW" nocase
    condition:
        any of them
}
YARA

run_tool "07_yara_basic_hits.txt" yara "$OUT/basic_maldoc_triage.yar" "$TARGET"

echo "[+] Running oletools..."
command -v oleid >/dev/null 2>&1 && run_tool "10_oleid.txt" oleid "$TARGET"
command -v olevba >/dev/null 2>&1 && run_tool "11_olevba_analysis.txt" olevba -a "$TARGET"
command -v mraptor >/dev/null 2>&1 && run_tool "12_mraptor.txt" mraptor "$TARGET"
command -v msodde >/dev/null 2>&1 && run_tool "13_msodde.txt" msodde "$TARGET"

echo "[+] Running oledump..."
run_tool "20_oledump_streams.txt" python3 "$TOOLS/DidierStevensSuite/oledump.py" "$TARGET"

echo "[+] Trying Excel 4.0 / XLM macro deobfuscation..."
if command -v XLMDeobfuscator >/dev/null 2>&1; then
  run_tool "30_xlmdeobfuscator.txt" XLMDeobfuscator --file "$TARGET"
else
  echo "XLMDeobfuscator command not available or install failed." > "$OUT/30_xlmdeobfuscator.txt"
fi

echo "[+] Checking if document is ZIP/OpenXML..."
SIZE_BYTES="$(stat -c%s "$TARGET")"
MAX_EXTRACT_SIZE=$((50 * 1024 * 1024))

if [[ "$SIZE_BYTES" -le "$MAX_EXTRACT_SIZE" ]] && 7z l "$TARGET" >/dev/null 2>&1; then
  run_tool "40_archive_listing_7z.txt" 7z l "$TARGET"

  mkdir -p "$OUT/41_extracted_openxml"
  7z x -y "-o$OUT/41_extracted_openxml" "$TARGET" > "$OUT/41_extract_log.txt" 2>&1 || true

  echo "[+] Grepping extracted OpenXML content..."
  grep -IRaE \
    '(https?://|hxxps?://|www\.|Target=|External|powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|vbaProject|oleObject|DDE|DDEAUTO)' \
    "$OUT/41_extracted_openxml" \
    > "$OUT/42_openxml_suspicious_refs.txt" 2>/dev/null || true
else
  echo "Not extracted. Either not ZIP/OpenXML or file larger than 50MB." > "$OUT/40_archive_listing_7z.txt"
fi

echo "[+] Building quick report..."
{
  echo "Maldoc Static Analysis Report"
  echo "============================"
  echo
  echo "Target: $TARGET"
  echo "Output Folder: $OUT"
  echo
  echo "Start with these files:"
  echo "- 00_hashes_filetype.txt"
  echo "- 05_iocs_raw.txt"
  echo "- 06_suspicious_strings.txt"
  echo "- 10_oleid.txt"
  echo "- 11_olevba_analysis.txt"
  echo "- 12_mraptor.txt"
  echo "- 13_msodde.txt"
  echo "- 20_oledump_streams.txt"
  echo "- 30_xlmdeobfuscator.txt"
  echo "- 42_openxml_suspicious_refs.txt"
  echo
  echo "Notes:"
  echo "- This script performs static triage only."
  echo "- Do not open the document in Office/LibreOffice on your host."
  echo "- Treat extracted IOCs as leads, not confirmed malicious infrastructure."
} > "$OUT/README_REPORT.txt"

echo
echo "[+] Done."
echo "[+] Report folder: $OUT"
echo "[+] Read first: $OUT/README_REPORT.txt"