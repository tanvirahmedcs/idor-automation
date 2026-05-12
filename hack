#!/usr/bin/env bash
set -euo pipefail

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"
log() { echo -e "${BLUE}[+]${RESET} $*"; }
ok()  { echo -e "${GREEN}[✓]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[!]${RESET} $*"; }
err() { echo -e "${RED}[-]${RESET} $*"; }

TOOLS=(
  subfinder httpx gau waybackurls katana nuclei gf sqlmap dirsearch go python3
)

install_tool() {
  local t="$1"
  case "$t" in
    subfinder) go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
    httpx) go install github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
    gau) go install github.com/lc/gau/v2/cmd/gau@latest ;;
    waybackurls) go install github.com/tomnomnom/waybackurls@latest ;;
    katana) go install github.com/projectdiscovery/katana/cmd/katana@latest ;;
    nuclei) go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ;;
    gf)
      go install github.com/tomnomnom/gf@latest
      mkdir -p ~/.gf
      git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/Gf-Patterns 2>/dev/null || true
      cp ~/.gf/Gf-Patterns/*.json ~/.gf/ 2>/dev/null || true
      ;;
    sqlmap) sudo apt install -y sqlmap ;;
    dirsearch)
      git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch 2>/dev/null || true
      ;;
    go) sudo apt install -y golang ;;
    python3) sudo apt install -y python3 python3-pip ;;
  esac
}

check_tools() {
  log "Checking tools..."
  mkdir -p ~/tools

  for t in "${TOOLS[@]}"; do
    if ! command -v "$t" &>/dev/null; then
      warn "$t missing → installing..."
      install_tool "$t"
    else
      ok "$t OK"
    fi
  done

  # Extra tools
  if ! command -v xsstrike &>/dev/null; then
    log "Installing XSStrike..."
    git clone https://github.com/s0md3v/XSStrike ~/tools/XSStrike 2>/dev/null || true
    pip3 install -r ~/tools/XSStrike/requirements.txt
  fi

  if ! command -v dalfox &>/dev/null; then
    log "Installing Dalfox..."
    go install github.com/hahwul/dalfox/v2@latest
  fi

  if ! command -v subjs &>/dev/null; then
    go install github.com/lc/subjs@latest
  fi

  if ! command -v gowitness &>/dev/null; then
    go install github.com/sensepost/gowitness@latest
  fi

  if ! command -v linkfinder &>/dev/null; then
    pip3 install linkfinder
  fi

  if ! command -v waymore &>/dev/null; then
    git clone https://github.com/xnl-h4ck3r/waymore ~/tools/waymore 2>/dev/null || true
    pip3 install -r ~/tools/waymore/requirements.txt
  fi

  ok "All tools ready."
}

DOMAIN=""
OUTDIR=""

init_target() {
  DOMAIN="$1"
  OUTDIR="$HOME/recon/$DOMAIN"
  mkdir -p "$OUTDIR"/{subdomains,live,urls,js,idor,auth,manual,dirsearch,nuclei,gf,sqlmap,xssstrike,screenshots,report,logs}
  ok "Workspace: $OUTDIR"
}

run_subfinder() {
  log "Running subfinder..."
  subfinder -d "$DOMAIN" -all -silent | sort -u | tee "$OUTDIR/subdomains/subfinder.txt"
}

probe_live() {
  log "Probing live hosts..."
  cat "$OUTDIR/subdomains/subfinder.txt" \
    | httpx -silent -status-code -title -tech-detect -follow-redirects \
    | tee "$OUTDIR/live/live_with_status.txt"

  awk '{print $1}' "$OUTDIR/live/live_with_status.txt" \
    | sort -u > "$OUTDIR/live/live_hosts.txt"
}

collect_urls() {
  log "Collecting URLs..."

  cat "$OUTDIR/live/live_hosts.txt" | gau | tee "$OUTDIR/urls/gau.txt"
  cat "$OUTDIR/live/live_hosts.txt" | waybackurls | tee "$OUTDIR/urls/wayback.txt"

  python3 ~/tools/waymore/waymore.py -i "$DOMAIN" -mode U -oU "$OUTDIR/urls/waymore_raw.txt" &>/dev/null || true
  cat "$OUTDIR/urls/waymore_raw.txt" | tee "$OUTDIR/urls/waymore.txt"

  katana -list "$OUTDIR/live/live_hosts.txt" -silent -depth 3 -jsl \
    | tee "$OUTDIR/urls/katana.txt"

  cat "$OUTDIR"/urls/*.txt | sort -u | tee "$OUTDIR/urls/all_urls.txt"
}

extract_paths_js() {
  log "Extracting paths + JS..."

  cat "$OUTDIR/urls/all_urls.txt" \
    | awk -F'//' '{print $2}' | awk -F'/' '{ $1=""; print "/"$0 }' \
    | sed 's#//#/#g' | sort -u \
    | tee "$OUTDIR/manual/paths.txt"

  grep -Ei '\.js(\?|$)' "$OUTDIR/urls/all_urls.txt" | sort -u \
    | tee "$OUTDIR/js/js_urls.txt"
}

analyze_js() {
  log "JS analysis..."

  cat "$OUTDIR/live/live_hosts.txt" | subjs | sort -u \
    | tee "$OUTDIR/js/subjs_urls.txt"

  cat "$OUTDIR/js/js_urls.txt" "$OUTDIR/js/subjs_urls.txt" \
    | sort -u | tee "$OUTDIR/js/all_js_urls.txt"

  while read -r js; do
    [ -z "$js" ] && continue
    python3 -m linkfinder -i "$js" -o cli \
      | tee -a "$OUTDIR/js/linkfinder_raw.txt"
  done < "$OUTDIR/js/all_js_urls.txt"

  cat "$OUTDIR/js/linkfinder_raw.txt" | sort -u \
    | tee "$OUTDIR/js/js_endpoints.txt"
}

run_dirsearch() {
  log "Dirsearch..."
  while read -r host; do
    python3 ~/tools/dirsearch/dirsearch.py -u "$host" -e php,asp,aspx,jsp,js,html,txt \
      -o "$OUTDIR/dirsearch/$(echo "$host" | sed 's#https\?://##').txt" \
      &>> "$OUTDIR/logs/dirsearch.log"
  done < "$OUTDIR/live/live_hosts.txt"
}

run_nuclei() {
  log "Running nuclei..."
  nuclei -update-templates &>/dev/null || true

  nuclei -l "$OUTDIR/live/live_hosts.txt" -severity low,medium,high,critical \
    -o "$OUTDIR/nuclei/hosts.txt"

  nuclei -l "$OUTDIR/urls/all_urls.txt" -severity low,medium,high,critical \
    -o "$OUTDIR/nuclei/urls.txt"
}

run_gf_sqlmap() {
  log "GF patterns..."

  cat "$OUTDIR/urls/all_urls.txt" | gf sqli | sort -u \
    | tee "$OUTDIR/gf/sqli.txt"

  cat "$OUTDIR/urls/all_urls.txt" | gf xss | sort -u \
    | tee "$OUTDIR/gf/xss.txt"

  cat "$OUTDIR/urls/all_urls.txt" | gf lfi | sort -u \
    | tee "$OUTDIR/gf/lfi.txt"

  log "SQLMap..."
  while read -r url; do
    sqlmap -u "$url" --batch --random-agent --level=5 --risk=3 \
      --tamper=space2comment,between,randomcase \
      --technique=BEUST --dbs \
      -o --output-dir="$OUTDIR/sqlmap" \
      &>> "$OUTDIR/logs/sqlmap.log"
  done < "$OUTDIR/gf/sqli.txt"
}

run_xssstrike() {
  log "XSStrike..."

  while read -r url; do
    python3 ~/tools/XSStrike/xsstrike.py -u "$url" --crawl --blind --fuzzer \
      --log-file "$OUTDIR/xssstrike/$(echo "$url" | md5sum | cut -d' ' -f1).log" \
      | tee -a "$OUTDIR/xssstrike/results.txt"

    gowitness single --url "$url" -P "$OUTDIR/screenshots/xss" &>/dev/null || true
  done < "$OUTDIR/gf/xss.txt"
}

idor_engine() {
  log "IDOR/BAC engine..."

  grep -E "id=|user=|uid=|account=|profile=|order=|invoice=|request=|submission=" \
    "$OUTDIR/urls/all_urls.txt" | sort -u \
    | tee "$OUTDIR/idor/idor_candidates.txt"

  while read -r url; do
    for i in 1 2 5 10 50 100 999 1337; do
      testurl=$(echo "$url" | sed "s/[0-9]\+/$i/g")
      curl -s -I "$testurl" | tee -a "$OUTDIR/idor/idor_testcases.txt"
    done
  done < "$OUTDIR/idor/idor_candidates.txt"
}

take_screenshots() {
  log "Screenshots..."
  gowitness file -f "$OUTDIR/live/live_hosts.txt" -P "$OUTDIR/screenshots" &>/dev/null || true
}

generate_report() {
  REPORT="$OUTDIR/report/$DOMAIN-report.md"
  log "Generating report..."

  {
    echo "# Report for $DOMAIN"
    echo "Generated: $(date)"
    echo
    echo "## Subdomains"
    cat "$OUTDIR/subdomains/subfinder.txt" | head -n 50
    echo
    echo "## Live Hosts"
    cat "$OUTDIR/live/live_with_status.txt" | head -n 50
    echo
    echo "## URLs"
    echo "Total: $(wc -l < "$OUTDIR/urls/all_urls.txt")"
    echo
    echo "## JS Endpoints"
    cat "$OUTDIR/js/js_endpoints.txt" | head -n 50
    echo
    echo "## Nuclei Findings"
    cat "$OUTDIR/nuclei/hosts.txt" | head -n 50
    echo
    echo "## SQLMap"
    echo "See sqlmap/ directory"
    echo
    echo "## XSSStrike"
    echo "See xssstrike/ directory"
    echo
    echo "## IDOR/BAC"
    echo "See idor/ directory"
  } > "$REPORT"

  ok "Report saved: $REPORT"
}

usage() {
  echo "Usage: hack -d example.com"
  exit 1
}

main() {
  if [ "$#" -lt 2 ]; then usage; fi

  while getopts ":d:" opt; do
    case "$opt" in
      d) DOMAIN="$OPTARG" ;;
      *) usage ;;
    esac
  done

  check_tools
  init_target "$DOMAIN"

  run_subfinder
  probe_live
  collect_urls
  extract_paths_js
  analyze_js
  run_dirsearch
  run_nuclei
  run_gf_sqlmap
  run_xssstrike
  idor_engine
  take_screenshots
  generate_report

  ok "Pipeline completed for $DOMAIN"
}

main "$@"
