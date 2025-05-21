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
  echo "  path          - Fuzzing direktori/path (default)"
  echo "  ext           - Fuzzing ekstensi file (contoh: indexFUZZ)"
  echo "  subdomain     - Subdomain enumeration menggunakan vhost"
  echo "  paramget      - parameter enumeration"
  echo "  vhost         - Vhost enumeration menggunakan header Host"
  echo "  parampostphp  - Mencari parameter valid dengan POST Method"
  echo "  postphpcustom - Melakukan POST Method aplikasi PHP dengan custom wordlist dan lokasi FUZZ"
  echo "  getcustom     - Melakukan GET Method aplikasi dengan custom wordlist dan lokasi FUZZ"
  echo "Contoh:"
  echo "  $0 path http://target.com:3021/FUZZ"
  echo "  $0 ext http://target.com:3021/indexFUZZ"
  echo "  $0 vhost http://target.com:3021"
  echo "  $0 subdomain http://target.com"
  echo "  $0 paramget http://target.com:30241/admin/admin.php?FUZZ=key"
  echo "  $0 parampostphp http://target.com:30241/admin/admin.php"
  echo "  $0 postphpcustom http://target.com:30241/admin/admin.php"
  echo "  $0 getcustom http://target.com:30241/reset_password.php?token=FUZZ -fr 'report The provided token is invalid'"
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

# Cek apakah server merespons
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" "$RAW_URL")
if [ -z "$HTTP_STATUS" ]; then
  handle_error "Tidak mendapat respons dari server: $RAW_URL"
else
  echo "[INFO] Server merespon dengan status code: $HTTP_STATUS"
fi

# Cek mode dan konfigurasi opsi tambahan
if [ "$MODE" == "path" ]; then
  # Tanya apakah pakai recursion
  read -p "Aktifkan recursion? (y/n, default: n):" RECURSION_ANSWER
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
  # Menyusun perintah ffuf
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\"" 
  
  # Jika recursion diaktifkan, tambahkan flag recursion dan depth
  if [ "$RECURSION" == true ]; then
    ffuf_cmd="$ffuf_cmd -recursion -recursion-depth $DEPTH"
  fi
elif [ "$MODE" == "ext" ]; then
  # Memastikan URL sudah berisi FUZZ, jika tidak tambahkan
  if [[ "$FULL_URL" != *"FUZZ"* ]]; then
    handle_error "URL harus mengandung FUZZ untuk melakukan fuzzing ekstensi."
  fi
  # URL menjadi alamat pengguna tanpa perubahan, hanya mengganti FUZZ
  URL="$FULL_URL"
  # Tentukan wordlist ekstensi
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/web-extensions.txt"

  # Menyusun perintah ffuf
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\"" 

elif [ "$MODE" == "subdomain" ]; then
  WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  SCHEME=$(echo "$FULL_URL" | grep -Eo '^https?')
  DOMAIN=$(echo "$FULL_URL" | sed -E 's#https?://([^/]+).*#\1#')
  URL="${SCHEME}://FUZZ.${DOMAIN}"
  # Menyusun perintah ffuf
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\""
elif [ "$MODE" == "paramget" ]; then
  if [[ "$FULL_URL" != *FUZZ* ]]; then
    handle_error "Mode 'paramget' memerlukan URL yang mengandung FUZZ pada posisi parameter."
  fi
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
  URL="$FULL_URL"
  # Menyusun perintah ffuf
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\""
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
  # Menyusun perintah ffuf
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\""
elif [ "$MODE" == "parampostphp" ]; then
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
  URL="$FULL_URL"
  # Tentukan data POST untuk menggunakan FUZZ pada parameter
  POST_DATA="FUZZ=key"
  HEADER="Content-Type: application/x-www-form-urlencoded"

  # Menyusun perintah ffuf dengan metode POST
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -X POST -d \"$POST_DATA\" -H \"$HEADER\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\""
elif [ "$MODE" == "postphpcustom" ]; then
  # Menanyakan lokasi wordlist kustom
  read -p "Masukkan path wordlist kustom: " CUSTOM_WORDLIST
  if [ ! -f "$CUSTOM_WORDLIST" ]; then
    handle_error "Wordlist tidak ditemukan: $CUSTOM_WORDLIST. Pastikan file wordlist ada di sistem."
  fi
  # Menanyakan POST_DATA kustom
  read -p "Masukkan POST_DATA kustom (gunakan FUZZ untuk parameter yang ingin difuzzing): " CUSTOM_POST_DATA
  if [[ ! "$CUSTOM_POST_DATA" == *"FUZZ"* ]]; then
    handle_error "POST_DATA harus mengandung FUZZ sebagai tempat pengganti parameter."
  fi

  URL="$FULL_URL"
  POST_DATA="$CUSTOM_POST_DATA"
  WORDLIST="$CUSTOM_WORDLIST"
  HEADER="Content-Type: application/x-www-form-urlencoded"

  # Menyusun perintah ffuf dengan metode POST custom
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -X POST -d \"$POST_DATA\" -H \"$HEADER\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\""

elif [ "$MODE" == "getcustom" ]; then
  # Menanyakan lokasi wordlist kustom
  read -p "Masukkan path wordlist kustom: " CUSTOM_WORDLIST
  if [ ! -f "$CUSTOM_WORDLIST" ]; then
    handle_error "Wordlist tidak ditemukan: $CUSTOM_WORDLIST. Pastikan file wordlist ada di sistem."
  fi

  URL="$FULL_URL"
  WORDLIST="$CUSTOM_WORDLIST"

  # Menyusun perintah ffuf dengan metode GET custom
  ffuf_cmd="ffuf -w \"$WORDLIST:FUZZ\" -u \"$URL\" -ic -v -t \"$THREADS\" -of csv -ac -o \"$OUTPUT\" $EXTRA_FLAGS $EXTENSIONS -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\""


else
  handle_error "Mode tidak dikenali: $MODE. Cek Help"
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

# Eksekusi perintah ffuf
echo "Executing command: $ffuf_cmd"
eval $ffuf_cmd

# Parsing hasil: ambil hanya URL status 200
echo -e "\n[+] Hasil URL yang ditemukan (status 200):"
tail -n +2 "$OUTPUT" | awk -F, '$5 == 200 { print $2 }'
