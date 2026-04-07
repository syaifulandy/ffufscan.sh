#!/bin/bash

# ==========================================
# FFUF Scanner Final (Smart Mode + Redirect Grouping)
# Output Bersih + Final Destination Check
# ==========================================

handle_error() {
  echo "[ERROR] $1"
  exit 1
}

# ==============================
# Usage
# ==============================
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <mode> <url> [target_domain] [options]"
  echo ""
  echo "Mode:"
  echo "  path      - directory fuzzing (target.com/FUZZ)"
  echo "  ext       - extension fuzzing (target.com/indexFUZZ)"
  echo "  subdomain - FUZZ.domain.com"
  echo "  vhost     - Host: FUZZ.domain.com"
  echo "  paramget  - ?FUZZ=value"
  echo ""
  echo "Contoh Vhost (HTB Style):"
  echo "  $0 vhost http://10.129.203.101 inlanefreight.local -fs 15157"
  echo ""
  exit 1
fi

# ==============================
# Config & Variables
# ==============================
MODE="$1"
FULL_URL="$2"
RAW_URL=$(echo "$FULL_URL" | sed -E 's#(https?://[^/]+).*#\1#')

THREADS=150
SAFE_NAME=$(echo "$FULL_URL" | sed -E 's#https?://##; s#[/?]#_#g; s#[^a-zA-Z0-9._-]#_#g')

OUTPUT_RAW="${SAFE_NAME}_output.csv"
OUTPUT_CLEAN="${SAFE_NAME}_output_bersih.csv"

USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126 Safari/537.36"

# Wordlist Setup
WL_DIR="/usr/share/seclists/Discovery/Web-Content"
WL_COMBINED="$WL_DIR/wordlist_combined.txt"

# Create combined wordlist if missing
if [ ! -f "$WL_COMBINED" ] && [ "$MODE" == "path" ]; then
  echo "[*] Membuat wordlist gabungan..."
  cat "$WL_DIR/quickhits.txt" \
      "$WL_DIR/common.txt" \
      "$WL_DIR/raft-small-directories.txt" \
  | sort -u > "$WL_COMBINED" || handle_error "Gagal buat wordlist"
fi

# ==============================
# Mode Setup & Domain Logic
# ==============================
shift 2
EXTRA_FLAGS=""

if [ "$MODE" == "vhost" ] || [ "$MODE" == "subdomain" ]; then
    # Jika parameter ke-3 adalah domain (bukan flag -), gunakan itu
    if [ -n "$1" ] && [[ "$1" != -* ]]; then
        TARGET_DOMAIN="$1"
        shift
    else
        # Jika tidak ada, ambil dari URL
        TARGET_DOMAIN=$(echo "$RAW_URL" | sed -E 's#https?://##' | sed 's#/##g')
    fi
    
    if [ "$MODE" == "vhost" ]; then
        WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
        URL="$RAW_URL/"
        EXTRA_FLAGS="-H Host:FUZZ.${TARGET_DOMAIN} $@"
    else
        WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
        SCHEME=$(echo "$RAW_URL" | grep -Eo '^https?')
        URL="${SCHEME}://FUZZ.${TARGET_DOMAIN}"
        EXTRA_FLAGS="$@"
    fi
elif [ "$MODE" == "path" ]; then
    WORDLIST="$WL_COMBINED"
    URL="$FULL_URL"
    EXTRA_FLAGS="$@"
elif [ "$MODE" == "ext" ]; then
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"
    URL="$FULL_URL"
    EXTRA_FLAGS="$@"
else
    URL="$FULL_URL"
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    EXTRA_FLAGS="$@"
fi

# ==============================
# Server Check
# ==============================
echo "[*] Checking server response..."
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" "$RAW_URL")
[[ "$HTTP_STATUS" == "000" ]] && handle_error "Server down: $RAW_URL"
echo "[INFO] Server OK: HTTP $HTTP_STATUS"

# ==============================
# Run FFUF
# ==============================
echo -e "\n[*] Running FFUF..."
echo "Mode     : $MODE"
echo "URL      : $URL"
echo "Wordlist : $WORDLIST"
echo "Flags    : $EXTRA_FLAGS"

ffuf -w "$WORDLIST:FUZZ" \
     -u "$URL" \
     -t "$THREADS" \
     -ic -ac \
     -of csv -o "$OUTPUT_RAW" \
     -H "User-Agent: $USER_AGENT" \
     $EXTRA_FLAGS

[[ ! -f "$OUTPUT_RAW" ]] && handle_error "FFUF gagal menghasilkan output!"

# ======================================================
# Step 2: Smart Cleaning + CURL Redirect Grouping
# ======================================================
echo -e "\n[*] Cleaning output & Checking Redirects (NO data loss)..."

awk -F',' -v OFS=',' -v mode="$MODE" -v dom="$TARGET_DOMAIN" '
function abs(x){ return x<0?-x:x }

NR==1 {
  print "target_found","status","size","redirect_to","final_destination_info"
  next
}

{
  fuzz=$1; url=$2; rloc=$3; status=$5; clen=$6; words=$7; lines=$8
  gsub(/^ +| +$/, "", status)

  # Logic Tampilan Target
  if (mode == "vhost" || mode == "subdomain") {
    display = fuzz "." dom
  } else {
    display = url
  }

  # 1. Keep 403 (Penting buat Pentest)
  if (status == "403") {
    print display, status, clen, rloc, "DIRECT_403"
    next
  }

  # 2. Redirect Grouping via CURL (PENTING!)
  if (status ~ /^30[12378]$/) {
    # Check final destination
    cmd = "curl -k -s -L -o /dev/null --max-time 2 -w \"%{http_code}_%{size_download}\" \"" url "\""
    cmd | getline res
    close(cmd)
    
    if (res == "") res = "TIMEOUT_0"
    
    # Grouping: Jika banyak vhost redirect ke page yang sama (status & size sama), ringkas.
    group_key = "REDIR_TO_" res
    if (!(seen[group_key]++)) {
      print display, status, clen, rloc, "FINAL_" res
    }
    next
  }

  # 3. Status 200 Deduplication
  if (status == "200") {
    base = words "|" lines
    found = 0
    for (k in oklen) {
      if (k == base && abs(clen - oklen[k]) <= 10) {
        found = 1; break
      }
    }
    if (!found) {
      oklen[base] = clen
      print display, status, clen, rloc, "UNIQUE_200"
    }
    next
  }

  # 4. Others (404, 500, etc)
  gen_key = "GEN|" status "|" clen
  if (!(seen[gen_key]++)) {
    print display, status, clen, rloc, "OTHER"
  }
}
' "$OUTPUT_RAW" > "$OUTPUT_CLEAN"

# ==============================
# Summary
# ==============================
echo -e "\n========== SUMMARY =========="
echo "[200 OK unique] : $(awk -F, '$2==200' "$OUTPUT_CLEAN" | grep -v "status" | wc -l)"
echo "[403 kept all]  : $(awk -F, '$2==403' "$OUTPUT_CLEAN" | wc -l)"
echo "[Redirects]     : $(awk -F, '$2 ~ /^30/' "$OUTPUT_CLEAN" | wc -l)"
echo "============================="
echo -e "\n[DONE] Hasil rapi ada di: $OUTPUT_CLEAN 🚀"
