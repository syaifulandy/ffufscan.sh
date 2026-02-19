#!/bin/bash

# ==========================================
# FFUF Scanner Final (Redirect Grouping Safe)
# Output Bersih Konsisten + No Data Loss
# Redirect Dedup + 200 Similar Size Grouping
# ==========================================

handle_error() {
  echo "[ERROR] $1"
  exit 1
}

# ==============================
# Usage
# ==============================
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <mode> <url>"
  echo ""
  echo "Mode:"
  echo "  path      - directory fuzzing"
  echo "  ext       - extension fuzzing (indexFUZZ)"
  echo "  subdomain - FUZZ.domain.com"
  echo "  vhost     - Host: FUZZ.domain.com"
  echo "  paramget  - ?FUZZ=value"
  echo ""
  echo "Example:"
  echo "  $0 path https://target.com/FUZZ"
  exit 1
fi

# ==============================
# Config
# ==============================
MODE="$1"
FULL_URL="$2"
RAW_URL=$(echo "$FULL_URL" | sed -E 's#(https?://[^/]+).*#\1#')

THREADS=150

OUTPUT_RAW="output.csv"
OUTPUT_CLEAN="output_bersih.csv"

WL_DIR="/usr/share/seclists/Discovery/Web-Content"
WL_COMBINED="$WL_DIR/wordlist_combined.txt"

USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126 Safari/537.36"

# ==============================
# Combine Wordlist (if missing)
# ==============================
if [ ! -f "$WL_COMBINED" ]; then
  echo "[*] Membuat wordlist gabungan..."
  cat "$WL_DIR/quickhits.txt" \
      "$WL_DIR/common.txt" \
      "$WL_DIR/directory-list-lowercase-2.3-small.txt" \
      > "$WL_COMBINED" || handle_error "Gagal buat wordlist gabungan"
fi

WORDLIST="$WL_COMBINED"
EXTRA_FLAGS=""

# ==============================
# Parse Extra Options
# ==============================
shift 2
while [ "$#" -gt 0 ]; do
  case "$1" in
    -fs) EXTRA_FLAGS="$EXTRA_FLAGS -fs $2"; shift 2 ;;
    -mc) EXTRA_FLAGS="$EXTRA_FLAGS -mc $2"; shift 2 ;;
    *) echo "[WARN] Unknown option: $1"; shift ;;
  esac
done

# ==============================
# Server Check
# ==============================
echo "[*] Checking server response..."
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" "$RAW_URL")

if [[ "$HTTP_STATUS" == "000" || -z "$HTTP_STATUS" ]]; then
  handle_error "Server tidak merespons: $RAW_URL"
fi
echo "[INFO] Server OK: HTTP $HTTP_STATUS"

# ==============================
# Mode Setup
# ==============================
if [ "$MODE" == "path" ]; then
  URL="$FULL_URL"

elif [ "$MODE" == "ext" ]; then
  [[ "$FULL_URL" != *FUZZ* ]] && handle_error "Mode ext butuh FUZZ di URL"
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"
  URL="$FULL_URL"

elif [ "$MODE" == "subdomain" ]; then
  WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  SCHEME=$(echo "$FULL_URL" | grep -Eo '^https?')
  DOMAIN=$(echo "$FULL_URL" | sed -E 's#https?://([^/]+).*#\1#')
  URL="${SCHEME}://FUZZ.${DOMAIN}"

elif [ "$MODE" == "vhost" ]; then
  WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  DOMAIN=$(echo "$RAW_URL" | awk -F[/:] '{print $4}')
  URL="$RAW_URL/"
  EXTRA_FLAGS="$EXTRA_FLAGS -H \"Host: FUZZ.${DOMAIN}\""

elif [ "$MODE" == "paramget" ]; then
  [[ "$FULL_URL" != *FUZZ* ]] && handle_error "Mode paramget butuh FUZZ"
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
  URL="$FULL_URL"

else
  handle_error "Mode tidak dikenali: $MODE"
fi

# ==============================
# Run FFUF
# ==============================
echo ""
echo "[*] Running FFUF..."
echo "Mode     : $MODE"
echo "URL      : $URL"
echo "Wordlist : $WORDLIST"
echo "Threads  : $THREADS"
echo ""

ffuf -w "$WORDLIST:FUZZ" \
     -u "$URL" \
     -t "$THREADS" \
     -ic -ac \
     -of csv -o "$OUTPUT_RAW" \
     -H "User-Agent: $USER_AGENT" \
     $EXTRA_FLAGS

[[ ! -f "$OUTPUT_RAW" ]] && handle_error "Output ffuf tidak ditemukan!"

echo ""
echo "[+] Raw output saved: $OUTPUT_RAW"

# ======================================================
# Step 2: Output Bersih Konsisten + Redirect Grouping FIX
# ======================================================

echo "[*] Cleaning output (NO redirect loss + NO duplicates)..."

awk -F',' -v OFS=',' '

function abs(x){ return x<0?-x:x }

NR==1 {
  print "url","redirectlocation","status_code","content_length","content_words","content_lines","redirect_group"
  next
}

{
  url=$2
  rloc=$3
  status=$5
  clen=$6
  words=$7
  lines=$8

  gsub(/^ +| +$/, "", status)

  # ==========================
  # Rule 1: Keep ALL 403 always
  # ==========================
  if (status=="403") {
    print url,rloc,status,clen,words,lines,"DIRECT_403"
    next
  }

  # ==========================
  # Rule 2: Redirect grouping + Deduplicate
  # ==========================
  if (status ~ /^30[12378]$/ && rloc!="") {

    cmd="curl -k -s -L -o /dev/null -w \"%{http_code} %{size_download}\" \"" url "\""
    cmd | getline result
    close(cmd)

    split(result,a," ")
    final_status=a[1]
    final_size=a[2]

    group="FINAL_" final_status "_SIZE_" final_size

    # Deduplicate identical redirect rows
    redir_key="R|"url"|"status"|"rloc"|"group

    if (!(redir_key in seen_redir)) {
      print url,rloc,status,clen,words,lines,group
      seen_redir[redir_key]=1
    }
    next
  }

  # ==========================
  # Rule 3: Status 200 grouping (±10 bytes)
  # ==========================
  if (status=="200") {

    base="OK|"words"|"lines

    if (!(base in base_len)) {
      base_len[base]=clen
      key=base
    }
    else {
      if (abs(clen - base_len[base]) <= 10) {
        key=base
      }
      else {
        key=base"|LEN"clen
      }
    }

    if (!(key in seen_ok)) {
      print url,rloc,status,clen,words,lines,"UNIQUE_200"
      seen_ok[key]=1
    }
    next
  }

  # ==========================
  # Rule 4: Other status dedupe
  # ==========================
  key="GEN|" status "|" clen "|" words "|" lines

  if (!(key in seen_other)) {
    print url,rloc,status,clen,words,lines,"UNIQUE_OTHER"
    seen_other[key]=1
  }

}

' "$OUTPUT_RAW" > "$OUTPUT_CLEAN"

echo ""
echo "[+] Clean output saved: $OUTPUT_CLEAN"

# ==============================
# Summary
# ==============================
echo ""
echo "========== SUMMARY =========="
echo "[200 OK unique] :" $(awk -F, '$3==200' "$OUTPUT_CLEAN" | wc -l)
echo "[403 kept all]  :" $(awk -F, '$3==403' "$OUTPUT_CLEAN" | wc -l)
echo "[Redirects]     :" $(awk -F, '$3 ~ /^30/' "$OUTPUT_CLEAN" | wc -l)
echo "============================="
echo ""
echo "[DONE] Output bersih aman + redirect grouped 🚀"
