#!/usr/bin/env bash

# ─────────────────────────────────────────────
#  Security Header Auditor — Ashen
#  Usage:
#    ./header_audit.sh -u https://example.com
#    ./header_audit.sh -U urllist.txt
#    ./header_audit.sh -u https://example.com -o report.txt
# ─────────────────────────────────────────────

# REMOVED set -euo pipefail — was silently killing execution on curl non-zero exit

# ── Colors ──────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Security Headers + Vuln Description ─────
declare -A HEADER_DESC
HEADER_DESC=(
  ["strict-transport-security"]="MISSING HSTS — Protocol downgrade & cookie hijacking (MitM)"
  ["content-security-policy"]="MISSING CSP — XSS, data injection, clickjacking via inline scripts"
  ["x-frame-options"]="MISSING X-Frame-Options — iFrame embedding → Clickjacking"
  ["x-content-type-options"]="MISSING X-Content-Type-Options — MIME sniffing attacks"
  ["referrer-policy"]="MISSING Referrer-Policy — Leaks sensitive URL data to third-parties"
  ["permissions-policy"]="MISSING Permissions-Policy — Uncontrolled camera/mic/geo API access"
  ["x-xss-protection"]="MISSING X-XSS-Protection — Legacy XSS filter disabled"
  ["cache-control"]="MISSING Cache-Control — Sensitive data cached by proxies/browsers"
  ["cross-origin-embedder-policy"]="MISSING COEP — Cross-origin isolation not enforced (Spectre)"
  ["cross-origin-opener-policy"]="MISSING COOP — Window/opener access unrestricted across origins"
  ["cross-origin-resource-policy"]="MISSING CORP — Resources embeddable by any cross-origin page"
  ["expect-ct"]="MISSING Expect-CT — Certificate Transparency not enforced"
  ["x-permitted-cross-domain-policies"]="MISSING X-Permitted-Cross-Domain — Adobe cross-domain uncontrolled"
)

declare -A SEVERITY
SEVERITY=(
  ["strict-transport-security"]="CRITICAL"
  ["content-security-policy"]="CRITICAL"
  ["x-frame-options"]="HIGH"
  ["x-content-type-options"]="MEDIUM"
  ["referrer-policy"]="MEDIUM"
  ["permissions-policy"]="MEDIUM"
  ["x-xss-protection"]="LOW"
  ["cache-control"]="MEDIUM"
  ["cross-origin-embedder-policy"]="HIGH"
  ["cross-origin-opener-policy"]="HIGH"
  ["cross-origin-resource-policy"]="HIGH"
  ["expect-ct"]="MEDIUM"
  ["x-permitted-cross-domain-policies"]="LOW"
)

declare -A REFERENCES
REFERENCES=(
  ["strict-transport-security"]="CWE-319 | OWASP A02:2021"
  ["content-security-policy"]="CWE-79  | OWASP A03:2021"
  ["x-frame-options"]="CWE-1021 | OWASP A05:2021"
  ["x-content-type-options"]="CWE-693 | OWASP A05:2021"
  ["referrer-policy"]="CWE-200 | OWASP A01:2021"
  ["permissions-policy"]="CWE-250 | OWASP A01:2021"
  ["x-xss-protection"]="CWE-79  | Legacy browsers"
  ["cache-control"]="CWE-524 | OWASP A02:2021"
  ["cross-origin-embedder-policy"]="CWE-346 | Spectre mitigation"
  ["cross-origin-opener-policy"]="CWE-346 | OWASP A05:2021"
  ["cross-origin-resource-policy"]="CWE-346 | OWASP A05:2021"
  ["expect-ct"]="RFC 9163"
  ["x-permitted-cross-domain-policies"]="Adobe Cross-Domain Policy"
)

OUTPUT_FILE=""
URLS=()
SUMMARY_CRITICAL=0
SUMMARY_HIGH=0
SUMMARY_MEDIUM=0
SUMMARY_LOW=0
TOTAL_URLS=0

usage() {
  echo -e "${BOLD}Usage:${RESET}"
  echo "  $0 -u <url>             Single URL"
  echo "  $0 -U <urllist.txt>     URL list from file"
  echo "  $0 -u <url> -o out.txt  Save to file"
  exit 1
}

while getopts ":u:U:o:h" opt; do
  case $opt in
    u) URLS+=("$OPTARG") ;;
    U)
      if [[ ! -f "$OPTARG" ]]; then
        echo -e "${RED}[!] File not found: $OPTARG${RESET}"
        exit 1
      fi
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        URLS+=("$line")
      done < "$OPTARG"
      ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ ${#URLS[@]} -eq 0 ]] && usage

for dep in curl awk grep sed; do
  if ! command -v "$dep" &>/dev/null; then
    echo -e "${RED}[!] Missing: $dep${RESET}"
    exit 1
  fi
done

out() {
  echo -e "$@"
  if [[ -n "$OUTPUT_FILE" ]]; then
    echo -e "$@" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
  fi
}

severity_color() {
  case "$1" in
    CRITICAL) echo -e "${RED}${BOLD}[CRITICAL]${RESET}" ;;
    HIGH)     echo -e "${MAGENTA}${BOLD}[HIGH]    ${RESET}" ;;
    MEDIUM)   echo -e "${YELLOW}[MEDIUM]  ${RESET}" ;;
    LOW)      echo -e "${CYAN}[LOW]     ${RESET}" ;;
  esac
}

bump_severity() {
  case "$1" in
    CRITICAL) ((SUMMARY_CRITICAL++)) ;;
    HIGH)     ((SUMMARY_HIGH++)) ;;
    MEDIUM)   ((SUMMARY_MEDIUM++)) ;;
    LOW)      ((SUMMARY_LOW++)) ;;
  esac
}

audit_url() {
  local url="$1"
  ((TOTAL_URLS++))

  out "\n${BOLD}${CYAN}════════════════════════════════════════════════════${RESET}"
  out "${BOLD}  TARGET » ${url}${RESET}"
  out "${BOLD}${CYAN}════════════════════════════════════════════════════${RESET}"

  # ── Fetch headers — no pipefail, capture exit code manually ──
  local raw_headers
  raw_headers=$(curl \
    --silent \
    --insecure \
    --location \
    --max-time 15 \
    --connect-timeout 8 \
    --max-redirs 5 \
    --dump-header - \
    --output /dev/null \
    --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    "$url" 2>/dev/null)

  local curl_exit=$?

  if [[ $curl_exit -ne 0 || -z "$raw_headers" ]]; then
    out "${RED}  [!] curl failed (exit: $curl_exit) — host unreachable or timeout${RESET}"
    out "${DIM}      Try: curl -v $url${RESET}"
    return
  fi

  # ── Normalize to lowercase keys ───────────────────────────────
  local normalized
  normalized=$(echo "$raw_headers" | awk '
    /^HTTP\// { print; next }
    /^[A-Za-z].*:/ {
      n = index($0, ":")
      if (n > 0) {
        key = substr($0, 1, n-1)
        val = substr($0, n+1)
        gsub(/^[ \t\r]+|[ \t\r]+$/, "", val)
        low = tolower(key)
        print low ": " val
      }
    }
  ')

  # ── HTTP Status ───────────────────────────────────────────────
  local status
  status=$(echo "$raw_headers" | grep -i "^HTTP/" | tail -1 | awk '{print $2}')
  out "  ${DIM}Status : HTTP ${status:-unknown}${RESET}"

  # ── Server banner leak ────────────────────────────────────────
  local server
  server=$(echo "$normalized" | grep "^server:" | head -1 | cut -d: -f2- | sed 's/^ //')
  if [[ -n "$server" ]]; then
    out "  ${YELLOW}⚠  Server Banner Exposed → ${server}${RESET}"
    out "  ${DIM}   Leaks stack info — useful for targeted exploits${RESET}"
  fi

  # ── HTTPS check ───────────────────────────────────────────────
  if [[ "$url" != https://* ]]; then
    out "  ${RED}✗  Not HTTPS — all traffic transmitted in plaintext${RESET}"
  fi

  # ── Cookie flags ──────────────────────────────────────────────
  local cookies
  cookies=$(echo "$normalized" | grep "^set-cookie:")
  if [[ -n "$cookies" ]]; then
    out ""
    out "  ${BOLD}Cookie Analysis:${RESET}"
    while IFS= read -r cookie_line; do
      local cval
      cval=$(echo "$cookie_line" | cut -d: -f2-)
      local cname
      cname=$(echo "$cval" | awk -F'=' '{print $1}' | sed 's/^ //')
      local flags=""
      echo "$cval" | grep -qi "httponly" || flags+="${RED}✗ HttpOnly  ${RESET}"
      echo "$cval" | grep -qi "secure"   || flags+="${RED}✗ Secure  ${RESET}"
      echo "$cval" | grep -qi "samesite" || flags+="${YELLOW}⚠ SameSite  ${RESET}"
      [[ -n "$flags" ]] && out "  ${DIM}Cookie [${cname}]${RESET} → $flags"
    done <<< "$cookies"
  fi

  out ""
  out "  ${BOLD}Missing Security Headers:${RESET}"
  out "  ──────────────────────────────────────────────────"

  local found_missing=0

  for header in "${!HEADER_DESC[@]}"; do
    if ! echo "$normalized" | grep -qi "^${header}:"; then
      local sev="${SEVERITY[$header]}"
      local label
      label=$(severity_color "$sev")
      bump_severity "$sev"
      ((found_missing++))
      out "  ${label} ${BOLD}${header}${RESET}"
      out "           ${DIM}↳ ${HEADER_DESC[$header]}${RESET}"
      out "           ${DIM}↳ ${REFERENCES[$header]}${RESET}"
    fi
  done

  if [[ $found_missing -eq 0 ]]; then
    out "  ${GREEN}✔  All monitored security headers present.${RESET}"
  fi

  out ""
  out "  ${BOLD}Present Headers:${RESET}"
  out "  ──────────────────────────────────────────────────"
  local found_present=0
  for header in "${!HEADER_DESC[@]}"; do
    local val
    val=$(echo "$normalized" | grep "^${header}:" | head -1 | cut -d: -f2- | sed 's/^ //')
    if [[ -n "$val" ]]; then
      ((found_present++))
      out "  ${GREEN}✔${RESET} ${BOLD}${header}${RESET}"
      out "    ${DIM}${val}${RESET}"
    fi
  done
  [[ $found_present -eq 0 ]] && out "  ${RED}None found.${RESET}"
}

print_summary() {
  local total_vulns=$((SUMMARY_CRITICAL + SUMMARY_HIGH + SUMMARY_MEDIUM + SUMMARY_LOW))
  out "\n${BOLD}${CYAN}════════════════════════════════════════════════════${RESET}"
  out "${BOLD}  SUMMARY — ${TOTAL_URLS} URL(s) | ${total_vulns} issues${RESET}"
  out "${BOLD}${CYAN}════════════════════════════════════════════════════${RESET}"
  out "  ${RED}${BOLD}CRITICAL :${RESET}  $SUMMARY_CRITICAL"
  out "  ${MAGENTA}${BOLD}HIGH     :${RESET}  $SUMMARY_HIGH"
  out "  ${YELLOW}MEDIUM   :${RESET}  $SUMMARY_MEDIUM"
  out "  ${CYAN}LOW      :${RESET}  $SUMMARY_LOW"

  if [[ $total_vulns -gt 10 ]]; then
    out "\n  ${RED}${BOLD}⚠  HIGH RISK — $total_vulns indicators detected${RESET}"
  elif [[ $total_vulns -gt 4 ]]; then
    out "\n  ${YELLOW}⚠  MODERATE RISK — $total_vulns indicators detected${RESET}"
  else
    out "\n  ${GREEN}✔  LOW RISK — $total_vulns indicators detected${RESET}"
  fi

  [[ -n "$OUTPUT_FILE" ]] && out "\n  ${DIM}Report saved → ${OUTPUT_FILE}${RESET}"
}

# ── Init ─────────────────────────────────────
[[ -n "$OUTPUT_FILE" ]] && > "$OUTPUT_FILE"

out "${BOLD}${MAGENTA}"
out "  ╔══════════════════════════════════════════════╗"
out "  ║      HTTP SECURITY HEADER AUDITOR            ║"
out "  ║              by Ashen  v2                    ║"
out "  ╚══════════════════════════════════════════════╝"
out "${RESET}"

for url in "${URLS[@]}"; do
  audit_url "$url"
done

print_summary
