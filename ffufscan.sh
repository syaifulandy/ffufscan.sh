#!/bin/bash

# Fungsi untuk menangani error dan menghentikan script
handle_error() {
  echo "[ERROR] $1"
  exit 1
}

# Cek jumlah argumen
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <mode> <url>"
  echo "Mode tersedia:"
  echo "  path     - Fuzzing direktori/path (default)"
  echo "  ext      - Fuzzing ekstensi file (contoh: indexFUZZ)"
  echo "  subdomain - Subdomain enumeration menggunakan vhost"
  echo "  vhost    - Vhost enumeration menggunakan header Host"
  echo "Contoh:"
  echo "  $0 path http://target.com/FUZZ"
  echo "  $0 ext http://target.com/indexFUZZ"
  echo "  $0 vhost http://target.com"
  echo "  $0 subdomain target.com"

  exit 1
fi

MODE="$1"
FULL_URL="$2"
RAW_URL=$(echo "$FULL_URL" | sed -E 's#(https?://[^/]+).*#\1#')
THREADS=150
OUTPUT="output.csv"
RECURSION=false
RECURSION_DEPTH=1
USE_EXTENSIONS=false
WORDLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt"
EXTENSIONS=""
EXTRA_FLAGS=""

# Parsing argumen tambahan
shift 2  # Hapus mode dan URL dari argumen
while [ "$#" -gt 0 ]; do
  case "$1" in
    -fs)
      EXTRA_FLAGS="$EXTRA_FLAGS -fs $2"
      shift 2
      ;;
    -mc)
      EXTRA_FLAGS="$EXTRA_FLAGS -mc $2"
      shift 2
      ;;
    *)
      echo "[WARNING] Opsi tidak dikenal: $1"
      shift
      ;;
  esac
done

# Pastikan ffuf terpasang
command -v ffuf > /dev/null 2>&1 || handle_error "ffuf tidak ditemukan, pastikan ffuf terinstal di sistem."

# Cek URL apakah valid (menggunakan curl)
if ! curl --output /dev/null --silent --head --fail "$RAW_URL"; then
  handle_error "URL tidak valid atau tidak dapat dijangkau: $RAW_URL"
fi

# Cek mode dan konfigurasi opsi tambahan
if [ "$MODE" == "path" ]; then
  # Tanya apakah pakai recursion
  read -p "Aktifkan recursion? (y/n, default: n): " RECURSION_ANSWER
  if [[ "$RECURSION_ANSWER" == "y" || "$RECURSION_ANSWER" == "Y" ]]; then
    RECURSION=true
    read -p "Masukkan depth recursion (default: 1): " DEPTH
    DEPTH=${DEPTH:-1}
  fi

  # Tanya apakah pakai ekstensi
  read -p "Pakai ekstensi? (y/n, default: n): " EXTENSION_ANSWER
  if [[ "$EXTENSION_ANSWER" == "y" || "$EXTENSION_ANSWER" == "Y" ]]; then
    USE_EXTENSIONS=true
    read -p "Masukkan ekstensi (misal: .php,.html): " EXTENSIONS
    EXTENSIONS="-e $EXTENSIONS"
  fi
  URL="${FULL_URL}"
elif [ "$MODE" == "ext" ]; then
  URL="${RAW_URL%/}FUZZ"  # Untuk ekstensi
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"
elif [ "$MODE" == "subdomain" ]; then
  WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  SCHEME=$(echo "$FULL_URL" | grep -Eo '^https?')
  DOMAIN=$(echo "$FULL_URL" | sed -E 's#https?://([^/]+).*#\1#')
  URL="${SCHEME}://FUZZ.${DOMAIN}"


elif [ "$MODE" == "vhost" ]; then
  WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  # Extract domain dan port dari URL
  DOMAIN=$(echo "$RAW_URL" | awk -F[/:] '{print $4}')
  PORT=$(echo "$RAW_URL" | awk -F[:] '{print $3}')
  PORT=${PORT:-80}

  # URL tetap tanpa FUZZ di path
  URL="http://${DOMAIN}:${PORT}/"  # URL tanpa FUZZ di path
  
  # Pastikan header menggunakan FUZZ untuk subdomain
  EXTRA_FLAGS="$EXTRA_FLAGS -H 'Host: FUZZ.${DOMAIN}'"
else
  handle_error "Mode tidak dikenali: $MODE. Gunakan 'path', 'ext', 'subdomain', atau 'vhost'."
fi

# Cek apakah wordlist ada
if [ ! -f "$WORDLIST" ]; then
  handle_error "Wordlist tidak ditemukan: $WORDLIST. Pastikan file wordlist ada di sistem."
fi

# Menampilkan informasi mode yang digunakan
echo "[*] Running ffuf..."
echo "Mode: $MODE"
echo "URL: $URL"
echo "Wordlist: $WORDLIST"
echo "Thread: $THREADS"
echo "Output: $OUTPUT"

# Menyusun perintah ffuf
ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS"

# Jika recursion diaktifkan, tambahkan flag recursion dan depth
if [ "$RECURSION" == true ]; then
  ffuf_cmd="$ffuf_cmd -recursion -recursion-depth $DEPTH"
fi

# Eksekusi perintah ffuf
echo "Executing command: $ffuf_cmd"
eval $ffuf_cmd

# Parsing hasil: ambil hanya URL status 200
echo -e "\n[+] Hasil URL yang ditemukan (status 200):"
tail -n +2 "$OUTPUT" | awk -F, '$5 == 200 { print $2 }'
