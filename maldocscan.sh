#!/usr/bin/env bash
# maldocscan.sh - static triage for suspicious documents (Office, PDF, RTF, archives)
#
# Usage:
#   ./maldocscan.sh [options] /path/to/sample
#
# Options:
#   --no-install     Skip package/pip/git setup. Use on snapshotted analysis VMs.
#   --setup-only     Run setup, then exit without analyzing.
#   --out DIR        Parent directory for the results folder. Default: $PWD
#   -h, --help       Show this help.
#
# Static analysis only. This script never executes the sample.

set -Eeuo pipefail

VERSION="2.0"
DO_INSTALL=1
SETUP_ONLY=0
OUT_PARENT="$PWD"
TARGET=""
TOOLS="${MALDOC_TOOLS:-$HOME/maldoc-tools}"
VENV="$TOOLS/venv"
DSS="$TOOLS/DidierStevensSuite"

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

log()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[X] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- args

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-install) DO_INSTALL=0; shift ;;
    --setup-only) SETUP_ONLY=1; shift ;;
    --out)        OUT_PARENT="${2:-}"; [[ -n "$OUT_PARENT" ]] || die "--out needs a directory"; shift 2 ;;
    -h|--help)    usage 0 ;;
    -*)           die "Unknown option: $1 (try --help)" ;;
    *)            TARGET="$1"; shift ;;
  esac
done

if [[ "$SETUP_ONLY" -eq 0 ]]; then
  [[ -n "$TARGET" ]] || usage 1
  [[ -f "$TARGET" ]] || die "Not a file: $TARGET"
  [[ -r "$TARGET" ]] || die "Not readable: $TARGET"
fi

# ---------------------------------------------------------------- setup

setup() {
  log "Installing OS packages (sudo may prompt)..."
  local SUDO=""
  [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

  $SUDO apt-get update
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git python3 python3-venv python3-pip \
    binutils file p7zip-full unzip yara libimage-exiftool-perl coreutils \
    || warn "Some packages failed to install; continuing."

  log "Setting up Python venv at $VENV ..."
  mkdir -p "$TOOLS"
  [[ -d "$VENV" ]] || python3 -m venv "$VENV"
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  python -m pip install --upgrade pip setuptools wheel

  log "Installing maldoc tools..."
  python -m pip install -U oletools olefile msoffcrypto-tool yara-python \
    || warn "oletools install had errors; check $VENV"

  python -m pip install -U "git+https://github.com/DissectMalware/XLMMacroDeobfuscator.git" \
    || warn "XLMMacroDeobfuscator install failed (optional)."

  log "Pulling Didier Stevens Suite..."
  if [[ -d "$DSS/.git" ]]; then
    git -C "$DSS" pull --ff-only || warn "DSS update failed; using existing copy."
  else
    git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite.git "$DSS" \
      || warn "DSS clone failed; PDF and oledump stages will be skipped."
  fi

  log "Setup complete."
}

if [[ "$DO_INSTALL" -eq 1 ]]; then
  setup
else
  log "Skipping install (--no-install)."
fi

[[ "$SETUP_ONLY" -eq 1 ]] && exit 0

# Activate venv if it exists, so oletools are on PATH even with --no-install.
if [[ -f "$VENV/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
else
  warn "No venv at $VENV. oletools stages will be skipped."
  warn "Run: $0 --setup-only"
fi

# ---------------------------------------------------------------- paths

TARGET="$(realpath "$TARGET")"
BASE="$(basename "$TARGET")"
SAFE_BASE="$(printf '%s' "$BASE" | tr -c 'A-Za-z0-9._-' '_')"
STAMP="$(date +'%Y%m%d_%H%M%S')"
OUT="$(realpath -m "$OUT_PARENT")/maldoc_analysis_${SAFE_BASE}_${STAMP}"

mkdir -p "$OUT"

log "Target:  $TARGET"
log "Output:  $OUT"

# ---------------------------------------------------------------- helpers

# run_tool <outfile> <cmd> [args...]
# Never aborts the script. Records the command line and any failure.
run_tool() {
  local outfile="$1"; shift
  log "Running: $*"
  {
    printf '$ %s\n\n' "$*"
    "$@" 2>&1
  } > "$OUT/$outfile" || printf '\n[!] Command exited non-zero: %s\n' "$*" >> "$OUT/$outfile"
  return 0
}

# run_if <command> <outfile> <cmd> [args...]
run_if() {
  local probe="$1"; shift
  local outfile="$1"; shift
  if command -v "$probe" >/dev/null 2>&1; then
    run_tool "$outfile" "$@"
  else
    printf '%s not found on PATH - stage skipped.\nCheck the venv at %s\n' "$probe" "$VENV" \
      > "$OUT/$outfile"
  fi
  return 0
}

# run_dss <script.py> <outfile> [args...]
run_dss() {
  local script="$1"; shift
  local outfile="$1"; shift
  if [[ -f "$DSS/$script" ]]; then
    run_tool "$outfile" python3 "$DSS/$script" "$@"
  else
    printf '%s not present under %s - stage skipped.\n' "$script" "$DSS" > "$OUT/$outfile"
  fi
  return 0
}

# ---------------------------------------------------------------- identify

log "Identifying file..."
FILE_DESC="$(file -b "$TARGET" 2>/dev/null || echo unknown)"
MIME="$(file -b --mime-type "$TARGET" 2>/dev/null || echo unknown)"
SIZE_BYTES="$(stat -c%s "$TARGET")"
EXT="${BASE##*.}"
EXT="$(printf '%s' "$EXT" | tr '[:upper:]' '[:lower:]')"

KIND="unknown"
case "$MIME" in
  application/pdf) KIND="pdf" ;;
  application/x-ole-storage|application/vnd.ms-*|application/msword|application/CDFV2*)
                   KIND="ole" ;;
  application/zip|application/vnd.openxmlformats-officedocument.*)
                   KIND="ooxml" ;;
  text/rtf|application/rtf) KIND="rtf" ;;
esac

# Extension as a fallback and as a mismatch signal.
case "$EXT" in
  pdf)                          EXT_KIND="pdf" ;;
  doc|xls|ppt|msg)              EXT_KIND="ole" ;;
  docx|docm|xlsx|xlsm|xlsb|pptx|pptm|dotm|xltm) EXT_KIND="ooxml" ;;
  rtf)                          EXT_KIND="rtf" ;;
  *)                            EXT_KIND="unknown" ;;
esac
[[ "$KIND" == "unknown" ]] && KIND="$EXT_KIND"

MISMATCH="no"
if [[ "$EXT_KIND" != "unknown" && "$KIND" != "unknown" && "$EXT_KIND" != "$KIND" ]]; then
  MISMATCH="yes"
  warn "Extension (.$EXT) does not match content type ($MIME). Noted in report."
fi

{
  echo "Target:        $TARGET"
  echo "Filename:      $BASE"
  echo "Analysis Time: $(date)"
  echo "Script:        maldocscan.sh v$VERSION"
  echo "Size (bytes):  $SIZE_BYTES"
  echo
  echo "File Type:     $FILE_DESC"
  echo "MIME:          $MIME"
  echo "Detected kind: $KIND"
  echo "Ext/content mismatch: $MISMATCH"
  echo
  echo "SHA256: $(sha256sum "$TARGET" | awk '{print $1}')"
  echo "SHA1:   $(sha1sum   "$TARGET" | awk '{print $1}')"
  echo "MD5:    $(md5sum    "$TARGET" | awk '{print $1}')"
} > "$OUT/00_hashes_filetype.txt"

run_if exiftool "01_exiftool_metadata.txt" exiftool "$TARGET"

# ---------------------------------------------------------------- strings

log "Extracting strings..."
strings -a -n 6    "$TARGET" > "$OUT/02_strings_ascii.txt"   2>/dev/null || true
strings -a -el -n 6 "$TARGET" > "$OUT/03_strings_utf16le.txt" 2>/dev/null || true
sort -u "$OUT/02_strings_ascii.txt" "$OUT/03_strings_utf16le.txt" \
  > "$OUT/04_strings_combined_unique.txt" 2>/dev/null || true

log "Extracting IOC candidates..."
grep -Eaio \
  '(https?://[^[:space:]"<>]+|hxxps?://[^[:space:]"<>]+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|([0-9]{1,3}\.){3}[0-9]{1,3}|[a-z0-9-]+\.(com|net|org|ru|cn|top|xyz|info|biz|io|co|us|uk|site|online|click|work|shop|tk|ml|ga))' \
  "$OUT/04_strings_combined_unique.txt" 2>/dev/null | sort -u > "$OUT/05_iocs_raw.txt" || true

log "Extracting suspicious command/macro strings..."
grep -Eai \
  '(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|curl |wget |Invoke-|IEX|FromBase64String|CreateObject|WScript\.Shell|Shell\.Application|WinHttpRequest|XMLHTTP|URLDownloadToFile|AutoOpen|Auto_Open|Document_Open|Workbook_Open|Workbook_Activate|DDEAUTO|Shell\(|StrReverse|ExecuteExcel4Macro|REGISTER\(|CALL\(|/OpenAction|/JavaScript|/Launch|/EmbeddedFile)' \
  "$OUT/04_strings_combined_unique.txt" 2>/dev/null > "$OUT/06_suspicious_strings.txt" || true

# ---------------------------------------------------------------- yara

cat > "$OUT/basic_maldoc_triage.yar" <<'YARA'
rule Basic_Suspicious_Maldoc_Static_Strings
{
    meta:
        description = "Static triage strings for suspicious documents"
        author      = "local triage"
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
        $e2 = "REGISTER(" nocase
        $e3 = "CALL(" nocase
        $b1 = "FromBase64String" nocase
        $b2 = "StrReverse" nocase
        $pdf1 = "/OpenAction" nocase
        $pdf2 = "/JavaScript" nocase
        $pdf3 = "/Launch" nocase
        $pdf4 = "/EmbeddedFile" nocase
    condition:
        any of them
}
YARA

run_if yara "07_yara_basic_hits.txt" yara "$OUT/basic_maldoc_triage.yar" "$TARGET"

# ---------------------------------------------------------------- office

analyze_office() {
  log "Office document stages..."
  run_if oleid   "10_oleid.txt"            oleid   "$TARGET"
  run_if olevba  "11_olevba_analysis.txt"  olevba  -a "$TARGET"
  run_if mraptor "12_mraptor.txt"          mraptor "$TARGET"
  run_if msodde  "13_msodde.txt"           msodde  "$TARGET"
  run_dss oledump.py "20_oledump_streams.txt" "$TARGET"

  if command -v xlmdeobfuscator >/dev/null 2>&1; then
    run_tool "30_xlmdeobfuscator.txt" xlmdeobfuscator --file "$TARGET"
  elif command -v XLMDeobfuscator >/dev/null 2>&1; then
    run_tool "30_xlmdeobfuscator.txt" XLMDeobfuscator --file "$TARGET"
  else
    echo "XLMDeobfuscator not installed - stage skipped." > "$OUT/30_xlmdeobfuscator.txt"
  fi
}

analyze_ooxml_container() {
  local max=$((50 * 1024 * 1024))
  if [[ "$SIZE_BYTES" -gt "$max" ]]; then
    echo "File larger than 50MB - not extracted." > "$OUT/40_archive_listing_7z.txt"
    return 0
  fi
  if ! command -v 7z >/dev/null 2>&1; then
    echo "7z not installed - stage skipped." > "$OUT/40_archive_listing_7z.txt"
    return 0
  fi
  if ! 7z l "$TARGET" >/dev/null 2>&1; then
    echo "Not a readable ZIP/OpenXML container." > "$OUT/40_archive_listing_7z.txt"
    return 0
  fi

  run_tool "40_archive_listing_7z.txt" 7z l "$TARGET"
  mkdir -p "$OUT/41_extracted_openxml"
  7z x -y "-o$OUT/41_extracted_openxml" "$TARGET" > "$OUT/41_extract_log.txt" 2>&1 || true

  log "Grepping extracted container..."
  grep -IRaE \
    '(https?://|hxxps?://|Target=|External|powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|vbaProject|oleObject|DDEAUTO)' \
    "$OUT/41_extracted_openxml" > "$OUT/42_openxml_suspicious_refs.txt" 2>/dev/null || true

  # External relationship targets are the highest-signal item here.
  grep -IRao 'Target="[^"]*"[^>]*TargetMode="External"' \
    "$OUT/41_extracted_openxml" > "$OUT/43_external_relationships.txt" 2>/dev/null || true
  [[ -s "$OUT/43_external_relationships.txt" ]] || \
    echo "No external relationship targets found." > "$OUT/43_external_relationships.txt"
}

# ---------------------------------------------------------------- pdf

analyze_pdf() {
  log "PDF stages..."
  run_dss pdfid.py "50_pdfid.txt" "$TARGET"
  run_dss pdf-parser.py "51_pdf_parser_stats.txt" -a "$TARGET"
  run_dss pdf-parser.py "52_pdf_openaction.txt"   -s /OpenAction "$TARGET"
  run_dss pdf-parser.py "53_pdf_javascript.txt"   -s /JavaScript "$TARGET"
  run_dss pdf-parser.py "54_pdf_launch.txt"       -s /Launch "$TARGET"
  run_dss pdf-parser.py "55_pdf_embeddedfile.txt" -s /EmbeddedFile "$TARGET"
  run_dss pdf-parser.py "56_pdf_uris.txt"         -s /URI "$TARGET"

  {
    echo "PDF follow-up commands (run manually on objects of interest):"
    echo
    echo "  python3 $DSS/pdf-parser.py -o <objnum> -f \"$TARGET\""
    echo "      -f applies stream filters so you see decoded content."
    echo
    echo "  python3 $DSS/pdf-parser.py -s /AA \"$TARGET\""
    echo "      Additional actions - another auto-trigger point."
    echo
    echo "Reading 50_pdfid.txt:"
    echo "  /OpenAction, /AA        fires on open"
    echo "  /JS, /JavaScript        embedded script"
    echo "  /Launch                 external program launch"
    echo "  /EmbeddedFile           carried payload"
    echo "  /URI                    outbound link (check 56_pdf_uris.txt)"
    echo
    echo "A PDF with zero active content but a single /URI is still likely"
    echo "phishing. Check 05_iocs_raw.txt and 56_pdf_uris.txt before closing."
  } > "$OUT/57_pdf_next_steps.txt"
}

# ---------------------------------------------------------------- rtf

analyze_rtf() {
  log "RTF stages..."
  run_if rtfobj "60_rtfobj.txt" rtfobj "$TARGET"
  run_dss rtfdump.py "61_rtfdump.txt" "$TARGET"
}

# ---------------------------------------------------------------- dispatch

case "$KIND" in
  pdf)   analyze_pdf ;;
  rtf)   analyze_rtf ;;
  ole)   analyze_office ;;
  ooxml) analyze_office; analyze_ooxml_container ;;
  *)
    warn "Unrecognized type - running all stages opportunistically."
    analyze_office
    analyze_ooxml_container
    analyze_pdf
    analyze_rtf
    ;;
esac

# Mismatched extension means the other family is worth a pass too.
if [[ "$MISMATCH" == "yes" ]]; then
  warn "Running $EXT_KIND stages as well due to type mismatch."
  case "$EXT_KIND" in
    pdf)   analyze_pdf ;;
    rtf)   analyze_rtf ;;
    ole|ooxml) analyze_office ;;
  esac
fi

# ---------------------------------------------------------------- report

IOC_COUNT=$(wc -l < "$OUT/05_iocs_raw.txt" 2>/dev/null || echo 0)
SUS_COUNT=$(wc -l < "$OUT/06_suspicious_strings.txt" 2>/dev/null || echo 0)

{
  echo "Maldoc Static Analysis Report"
  echo "============================"
  echo
  echo "Target:        $TARGET"
  echo "SHA256:        $(sha256sum "$TARGET" | awk '{print $1}')"
  echo "Detected kind: $KIND   (MIME: $MIME)"
  echo "Ext mismatch:  $MISMATCH"
  echo "Output folder: $OUT"
  echo
  echo "Quick counts:"
  echo "  IOC candidates:      $IOC_COUNT"
  echo "  Suspicious strings:  $SUS_COUNT"
  echo
  echo "Read in this order:"
  echo "  00_hashes_filetype.txt        identity and hashes"
  case "$KIND" in
    pdf)
      echo "  50_pdfid.txt                  active-content counts - START HERE"
      echo "  52_pdf_openaction.txt         auto-trigger actions"
      echo "  53_pdf_javascript.txt         embedded script"
      echo "  56_pdf_uris.txt               outbound links"
      echo "  57_pdf_next_steps.txt         manual follow-up commands"
      ;;
    rtf)
      echo "  60_rtfobj.txt                 embedded objects - START HERE"
      echo "  61_rtfdump.txt                control word structure"
      ;;
    *)
      echo "  11_olevba_analysis.txt        macro source and IOCs - START HERE"
      echo "  12_mraptor.txt                macro verdict"
      echo "  10_oleid.txt                  container indicators"
      echo "  13_msodde.txt                 DDE fields"
      echo "  20_oledump_streams.txt        stream layout"
      echo "  43_external_relationships.txt remote template / external refs"
      ;;
  esac
  echo "  06_suspicious_strings.txt     command and API hits"
  echo "  05_iocs_raw.txt               URLs, IPs, domains, emails"
  echo
  echo "Notes:"
  echo "- Static triage only. The sample was never executed."
  echo "- Do not open the sample in Office, a PDF reader, or a browser on your host."
  echo "- IOCs are leads, not confirmed malicious infrastructure. Verify before blocking."
  echo "- Clean output is not a clean verdict. Heavily obfuscated or"
  echo "  downloader-only samples look boring here. Escalate to detonation"
  echo "  when the delivery context is suspicious regardless of these results."
} > "$OUT/README_REPORT.txt"

echo
log "Done."
log "Report folder: $OUT"
log "Read first:    $OUT/README_REPORT.txt"
