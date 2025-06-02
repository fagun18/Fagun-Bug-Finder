#!/usr/bin/env bash
#
# all_url_xss_pipeline.sh
# -----------------------
# Enhanced and robust pipeline to find XSS endpoints:
# 1. Enumerate subdomains (Subfinder, Assetfinder, Amass, Findomain).
# 2. For each live subdomain (parallelized):
#      • HTTP/HTTPS 200 check via httpx (10s timeout).
#      • waybackurls  (retry up to 3 × 30s attempts).
#      • gauplus      (retry up to 3 × 30s attempts).
#      • katana crawl (one 30s attempt, depth=2).
# 3. Combine + dedupe all gathered URLs; filter for XSS candidates (gf xss + uro).
# 4. Run Gxss with payloads (chunked 500 lines, parallelized), then kxss to refine.
# 5. Extract and normalize “URL=<…>” (or plain URLs) into final.txt.
#
# Usage:
#   ./all_url_xss_pipeline.sh <root_domain> <payloads.txt> [<parallel_jobs>]
#
# Example:
#   ./all_url_xss_pipeline.sh vulnweb.com /home/fagun/loxs/payloads/xsspollygots.txt 8
#

set -euo pipefail
IFS=$'\n\t'

###############
#  USAGE HELP #
###############
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <root_domain> <payload_file> [<parallel_jobs>]"
  echo "Example: $0 vulnweb.com /home/fagun/loxs/payloads/xsspollygots.txt 8"
  exit 1
fi

ROOT_DOMAIN="$1"
PAYLOADS="$2"
PAR_JOBS="${3:-8}"   # Default to 8 parallel jobs

###########################
#  VERIFY PAYLOADS FILE   #
###########################
if [[ ! -f "$PAYLOADS" ]]; then
  echo "[!] Error: Payload file '$PAYLOADS' not found."
  exit 1
fi

######################################
#  SETUP TEMP DIRECTORIES + FILES    #
######################################
TMP_DIR="./tmp_xss_pipeline"
SUB_DIR="$TMP_DIR/subdomains"
URLS_DIR="$TMP_DIR/urls_raw"

COMBINED_URLS="$TMP_DIR/combined_urls.txt"
FILTERED_URLS="$TMP_DIR/filtered_urls.txt"
GXSS_OUTPUT="$TMP_DIR/gxss_output.txt"
FINAL_OUTPUT="$TMP_DIR/xss_output.txt"
FINAL_NORMALIZED="final.txt"

# Clean up any previous run
rm -rf "$TMP_DIR"
mkdir -p "$SUB_DIR" "$URLS_DIR"

echo "[*] Root domain: $ROOT_DOMAIN"
echo "[*] Payload file: $PAYLOADS"
echo "[*] Parallel jobs: $PAR_JOBS"
echo

############################################
# 1. SUBDOMAIN ENUMERATION (PASSIVE ONLY)  #
############################################
echo "[*] Enumerating subdomains (parallel & time-limited) ..."

# Subfinder
subfinder -silent -d "$ROOT_DOMAIN" > "$SUB_DIR/subfinder.txt" 2>/dev/null \
  || echo "[!] subfinder error/no output"

# Assetfinder
assetfinder --subs-only "$ROOT_DOMAIN" > "$SUB_DIR/assetfinder.txt" 2>/dev/null \
  || echo "[!] assetfinder error/no output"

# Amass (passive, 20s max)
timeout 20s amass enum -passive -d "$ROOT_DOMAIN" > "$SUB_DIR/amass.txt" 2>/dev/null \
  || echo "[!] amass timed out or error"

# Findomain
findomain -t "$ROOT_DOMAIN" -q > "$SUB_DIR/findomain.txt" 2>/dev/null \
  || echo "[!] findomain error/no output"

echo "[+] Subdomain enumeration complete."
echo "[*] Combining and deduplicating subdomains ..."

cat \
  "$SUB_DIR/subfinder.txt" \
  "$SUB_DIR/assetfinder.txt" \
  "$SUB_DIR/amass.txt" \
  "$SUB_DIR/findomain.txt" \
  | sed '/^\s*$/d' \
  | sort -u \
  > "$TMP_DIR/subdomains.txt"

SUB_COUNT=$(wc -l < "$TMP_DIR/subdomains.txt")
echo "[+] Found $SUB_COUNT unique subdomains (saved to subdomains.txt)"
echo

#########################################################
# 2. GATHER URLs FOR EACH SUBDOMAIN (PARALLELIZED)       #
#########################################################
echo "[*] Gathering URLs for each subdomain in parallel (timeout=30s per tool, with retries) ..."

# Function: for a given subdomain, check HTTP status and fetch URLs
gather_urls_for() {
  local sub="$1"
  local safe_sub
  safe_sub="$(echo "$sub" | sed 's/[:\/]/_/g')"   # sanitize for filenames

  # 2.1 Quick HTTP(S) check: require 200 within 10s; skip otherwise
  if ! echo "https://$sub" | httpx -silent -mc 200 -timeout 10 > /dev/null 2>&1; then
    echo "[!] Skipping $sub (no HTTP/HTTPS 200)" >&2
    return
  fi

  # 2.2 waybackurls (up to 3 × 30s attempts)
  local attempt=1
  while [[ $attempt -le 3 ]]; do
    if echo "$sub" | timeout 30s waybackurls > "$URLS_DIR/wayback_$safe_sub.txt" 2>/dev/null; then
      break
    else
      echo "[!] waybackurls $sub attempt #$attempt failed. Retrying..." >&2
      (( attempt++ ))
      sleep 2
    fi
  done
  if [[ $attempt -gt 3 ]]; then
    echo "[!] waybackurls $sub failed after 3 attempts." >&2
    : > "$URLS_DIR/wayback_$safe_sub.txt"   # create empty file
  fi

  # 2.3 gauplus (up to 3 × 30s attempts)
  attempt=1
  while [[ $attempt -le 3 ]]; do
    if echo "$sub" | timeout 30s gauplus > "$URLS_DIR/gauplus_$safe_sub.txt" 2>/dev/null; then
      break
    else
      echo "[!] gauplus $sub attempt #$attempt failed. Retrying..." >&2
      (( attempt++ ))
      sleep 2
    fi
  done
  if [[ $attempt -gt 3 ]]; then
    echo "[!] gauplus $sub failed after 3 attempts." >&2
    : > "$URLS_DIR/gauplus_$safe_sub.txt"
  fi

  # 2.4 katana crawl (one 30s attempt, depth=2)
  if ! echo "https://$sub" | timeout 30s katana -u - -depth 2 > "$URLS_DIR/katana_$safe_sub.txt" 2>/dev/null; then
    echo "[!] katana $sub timed out or error" >&2
    : > "$URLS_DIR/katana_$safe_sub.txt"
  fi
}

export -f gather_urls_for
export URLS_DIR

# Run gather_urls_for in parallel
cat "$TMP_DIR/subdomains.txt" \
  | xargs -P "$PAR_JOBS" -I {} bash -c 'gather_urls_for "$@"' _ {}

echo "[+] URL gathering complete for all subdomains."
echo

#############################################
# 3. COMBINE & DEDUPE ALL RAW URL FILES     #
#############################################
echo "[*] Combining all raw URL files and deduplicating ..."

find "$URLS_DIR" -maxdepth 1 -type f -name '*.txt' -print0 \
  | xargs -0 cat \
  | sed '/^\s*$/d' \
  | sort -u \
  > "$COMBINED_URLS"

COMBINED_COUNT=$(wc -l < "$COMBINED_URLS")
echo "[+] Combined raw URLs: $COMBINED_COUNT lines (saved to combined_urls.txt)"
echo

##########################################################
# 4. FILTER COMBINED URLs FOR XSS CANDIDATES (gf xss + uro) #
##########################################################
echo "[*] Filtering combined URLs for XSS (gf xss + uro) ..."

cat "$COMBINED_URLS" \
  | gf xss \
  | uro \
  | sed '/^\s*$/d' \
  | sort -u \
  > "$FILTERED_URLS"

FILTERED_COUNT=$(wc -l < "$FILTERED_URLS")
echo "[+] After gf xss + uro: $FILTERED_COUNT URLs remain (saved to filtered_urls.txt)"
echo

##################################################
# 5. RUN Gxss AGAINST FILTERED URLs (PARALLEL)   #
##################################################
echo "[*] Running Gxss against filtered URLs in parallel (500-line chunks) ..."

# Split filtered list into 500-line files
split -l 500 "$FILTERED_URLS" "$TMP_DIR/chunk_"

# Ensure GXSS_OUTPUT is empty (or create it)
> "$GXSS_OUTPUT"

run_gxss_chunk() {
  local chunk_file="$1"
  cat "$chunk_file" | Gxss -p "$PAYLOADS" 2>/dev/null >> "$GXSS_OUTPUT"
}
export -f run_gxss_chunk
export PAYLOADS
export GXSS_OUTPUT

ls "$TMP_DIR"/chunk_* \
  | xargs -P "$PAR_JOBS" -I {} bash -c 'run_gxss_chunk "$@"' _ {}

GXSS_COUNT=$(wc -l < "$GXSS_OUTPUT")
echo "[+] Gxss found $GXSS_COUNT potential XSS endpoints (saved to gxss_output.txt)"
echo

#############################################
# 6. RUN kxss TO DEDUPE/REFINE Gxss RESULTS  #
#############################################
echo "[*] Running kxss on Gxss output ..."

cat "$GXSS_OUTPUT" | kxss > "$FINAL_OUTPUT" 2>/dev/null \
  || echo "[!] kxss error/no output"

FINAL_COUNT=$(wc -l < "$FINAL_OUTPUT")
echo "[+] kxss refined list: $FINAL_COUNT URLs (saved to xss_output.txt)"
echo

####################################################
# 7. EXTRACT & NORMALIZE URLs INTO final.txt       #
####################################################
echo "[*] Normalizing final URLs into final.txt ..."

# Strip “URL: ” prefix if present, then normalize parameter values to “=”
cat "$FINAL_OUTPUT" \
  | sed -E 's/^URL: //' \
  | sed 's/=.*/=/' \
  | sort -u \
  > "$FINAL_NORMALIZED"

NORMALIZED_COUNT=$(wc -l < "$FINAL_NORMALIZED")
echo "[+] Extracted & normalized $NORMALIZED_COUNT entries into final.txt"
echo

####################
# 8. CLEAN UP      #
####################
echo "[*] Cleaning up temporary files ..."
rm -rf "$TMP_DIR"

echo "[*] Pipeline complete!"
echo "[*] Raw XSS‐filtered URLs: $(pwd)/$FINAL_OUTPUT"
echo "[*] Final normalized URL list: $(pwd)/$FINAL_NORMALIZED"
