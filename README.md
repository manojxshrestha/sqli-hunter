<p align="center">
  <img src="https://github.com/user-attachments/assets/8e38facd-36fe-46fa-be2b-7bfe15baebf0" alt="SQLi Hunter">
</p>


[![GitHub stars](https://img.shields.io/github/stars/manojxshrestha/sqli-hunter)](https://github.com/manojxshrestha/sqli-hunter/stargazers)  
[![GitHub forks](https://img.shields.io/github/forks/manojxshrestha/sqli-hunter)](https://github.com/manojxshrestha/sqli-hunter/network)

# SQLi Hunter - All-in-One Recon & Vuln Smasher 🧑🏻‍💻

SQLi Hunter is a powerful Bash script built by [me](https://github.com/manojxshrestha) to automate subdomain enumeration, URL crawling, parameter hunting, SQL injection testing, XSS probing with DalFox, and secret extraction. It’s a chaos-injecting pipeline with custom payloads in `payloads/`, designed to rip through targets and leave no vuln unturned.

---

## Features
- **Subdomain Enumeration**: `subfinder` + `crt.sh` for max coverage.
- **URL Crawling**: `katana` and `waymore` dig deep into target sites.
- **Parameter Extraction**: `gf`, `uro`, and `qsreplace` sniff out juicy params.
- **SQLi Testing**: `sqlmap` with custom payloads for blind, error, UNION, and OOB attacks.
- **XSS Hunting**: `dalfox` powers fast, stealthy XSS scans with custom payloads.
- **Secret Smashing**: Harvests sensitive PDFs, backups, cloud buckets, and API keys.
- **Stealth Mode**: `torsocks` + random delays for sneaky runs.
- **Reporting**: Detailed vuln and secret summaries with optional DB enumeration.
- **Modular Output**: Organized into `Recon/domain/{urls,parameters,Vuln,secrets}`.

---

### Tools
Here’s the arsenal—core tools are required, optional ones enhance functionality. Install them manually or via package managers, and ensure they’re in your `PATH`.

| Tool         | Purpose                  | Installation Command or Source                                      |
|--------------|--------------------------|--------------------------------------------------------------------|
| `subfinder`  | Subdomain enumeration    | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `curl`       | HTTP requests            | `sudo apt install curl` (Linux) or `brew install curl` (macOS)     |
| `jq`         | JSON parsing             | `sudo apt install jq` or `pacman -S jq`                           |
| `waymore`    | URL harvesting           | `pip install waymore`                                             |
| `katana`     | Web crawling             | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `httpx`      | HTTP probing             | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`   |
| `gf`         | Parameter filtering      | `go install github.com/tomnomnom/gf@latest`                       |
| `uro`        | URL deduplication        | `pip install uro`                                                 |
| `qsreplace`  | Query string replacement | `go install github.com/tomnomnom/qsreplace@latest`                |
| `sqlmap`     | SQLi exploitation        | `git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git` |
| `anew`       | Deduplication            | `go install github.com/tomnomnom/anew@latest`                     |
| `dalfox`     | XSS testing              | `go install github.com/hahwul/dalfox/v2@latest`                   |
| `pdftotext`  | PDF text extraction      | `sudo apt install poppler-utils` (optional, for secrets)          |
| `torsocks`   | Stealth via Tor          | `sudo apt install torsocks` (optional, for stealth mode)          |

#### Notes
- **Go Tools**: Need Go installed—run `go install` and add `$GOPATH/bin` to `PATH`.
- **Python**: `requests` and `termcolor` required for checks—`pip install requests termcolor`.
- **Optional Tools**: Skip `pdftotext` or `torsocks` if you don’t need secrets or stealth—just expect some features to gracefully skip.

---

## Installation

1. **Clone the Repo**:
   ```bash
   git clone https://github.com/manojxshrestha/sqli-hunter.git
   cd sqli-hunter
   ```

2. **Install Dependencies**:
   - Python packages:
     ```bash
     pip install requests termcolor
     ```
   - Core tools (example for `jq`):
     ```bash
     sudo apt install jq
     ```
   - Go tools (example for `dalfox`):
     ```bash
     go install github.com/hahwul/dalfox/v2@latest
     ```

3. **Verify Tools**:
   ```bash
   ./sqli-hunter.sh -t
   ```
   - Check output for missing tools and fix as needed.

4. **Payloads**:
   - Preloaded in `payloads/`:
     - `blind_boolean.txt`
     - `blind_time.txt`
     - `errors.txt`
     - `oob.txt`
     - `union.txt`
     - `xss.txt`

---

## Usage
```bash
./sqli-hunter.sh [-d domain.tld] [-l list.txt] [-s] [-m] [-a] [-p] [-o OUTPUT] [-v] [-w] [-r] [-S] [-x] [-y]
```
- **Targets**: `-d <domain>` (single) or `-l <list.txt>` (multi).
- **Modes**: `-s` (single), `-m` (multi), `-a` (all), `-p` (passive).
- **General**: `-o <output/path>` (default `./Recon`), `-t` (tools check), `-h` (help).
- **Advanced**: `-v` (verbose), `-w` (WAF evasion), `-r` (report), `-S` (stealth), `-x` (XSS), `-y` (verify SQLi).

### Examples
- Full chaos on a single target:
  ```bash
  ./sqli-hunter.sh -d http://testphp.vulnweb.com -s -v -w -r -S -x -y
  ```
- Passive multi-target recon:
  ```bash
  echo "http://testphp.vulnweb.com" > targets.txt
  ./sqli-hunter.sh -l targets.txt -m -p -o loot
  ```

---

### Flags
- **Targets**:
  - `-d <domain>`: Single target (e.g., `http://example.com`).
  - `-l <list.txt>`: File with multiple targets (one per line).
- **Modes**:
  - `-s` / `--single`: Scan just the target.
  - `-m` / `--multi`: Include subdomains.
  - `-a` / `--all`: Both single and multi scans.
  - `-p` / `--passive`: Recon only, no testing.
- **General**:
  - `-o <output>`: Output dir (default: `./Recon`).
  - `-t`: Check tools and exit.
  - `-h` / `--help`: Show usage.

---

## Payloads
Custom payloads in `payloads/` power the attacks:
- **SQLi**:
  - `blind_boolean.txt`: True/false checks (e.g., `1 AND 1=1`).
  - `blind_time.txt`: Delay injections (e.g., `1 AND SLEEP(5)`).
  - `errors.txt`: Error triggers (e.g., `1'`).
  - `oob.txt`: Out-of-band requests (e.g., `EXEC xp_dirtree`).
  - `union.txt`: UNION queries (e.g., `1 UNION SELECT 1,2,3`).
- **XSS**:
  - `xss.txt`: Basic XSS probes (e.g., `<script>alert(1)</script>`).

Adjust these to fit your targets!

---

## Usage Examples
Here’s every way to wield SQLi Hunter—15 combos to cover all bases!

### 1. Tool Check
```bash
./sqli-hunter.sh -t
```
- **What**: Lists tools and paths, flags missing ones.
- **Output**: `[+] subfinder - Found at /home/pwn/go/bin/subfinder ...`
- **Why**: Ensure your setup’s ready.

### 2. Help Menu
```bash
./sqli-hunter.sh -h
```
- **What**: Shows the usage guide.
- **Output**: Banner + `Usage: ./sqli-hunter.sh [-d domain.tld] ...`
- **Why**: Quick flag refresher.

### 3. Single Domain, Single Mode
```bash
./sqli-hunter.sh -d http://testphp.vulnweb.com -s
```
- **What**: Scans only the target, no subs, with SQLi tests.
- **Output**: `Found 50 URLs ... Hits - Blind Boolean: 2`
- **Why**: Fast vuln check on one site.

### 4. Single Domain, Multi Mode
```bash
./sqli-hunter.sh -d http://verily.com -m
```
- **What**: Scans target + subdomains.
- **Output**: `Found 20 subs ... Found 200 URLs`
- **Why**: Deep dive with subs.

### 5. Single Domain, All Modes
```bash
./sqli-hunter.sh -d http://example.com -a
```
- **What**: Runs single + multi scans.
- **Output**: `Single scan ... Multi-level scan ...`
- **Why**: Maximum coverage.

### 6. Passive Recon
```bash
./sqli-hunter.sh -d http://example.com -p -m
```
- **What**: Multi-mode recon, no active tests.
- **Output**: `No params to test or passive mode—skipping tests`
- **Why**: Stealthy intel grab.

### 7. Custom Output
```bash
./sqli-hunter.sh -d http://testphp.vulnweb.com -s -o ./loot
```
- **What**: Single scan, results in `./loot/`.
- **Output**: `Done! Loot’s in ./loot`
- **Why**: Organize your way.

### 8. Verbose Debugging
```bash
./sqli-hunter.sh -d http://verily.com -m -v
```
- **What**: Multi-scan with full command logs.
- **Output**: `Running: subfinder -d verily.com ...`
- **Why**: Debug or geek out.

### 9. WAF Evasion
```bash
./sqli-hunter.sh -d http://example.com -m -w
```
- **What**: Multi-scan with WAF-dodging tricks.
- **Output**: `Running: sqlmap ... --random-agent ...`
- **Why**: Slip past protections.

### 10. Generate Report
```bash
./sqli-hunter.sh -d http://testphp.vulnweb.com -m -r
```
- **What**: Multi-scan with a `report.txt`.
- **Output**: `Report saved to ./Recon/testphp.vulnweb.com/report.txt`
- **Why**: Document hits.

### 11. Stealth Mode
```bash
./sqli-hunter.sh -d http://example.com -m -S
```
- **What**: Multi-scan with Tor + delays.
- **Output**: `Running: torsocks katana ...`
- **Why**: Stay sneaky.

### 12. XSS Testing
```bash
./sqli-hunter.sh -d http://testphp.vulnweb.com -s -x
```
- **What**: Single scan with XSS via DalFox.
- **Output**: `XSS Hits: 1`
- **Why**: Hunt XSS too.

### 13. Verify SQLi
```bash
./sqli-hunter.sh -d http://testphp.vulnweb.com -m -y
```
- **What**: Multi-scan, verifies SQLi with DB names.
- **Output**: `Verified SQLi Databases: vulnweb_db`
- **Why**: Confirm exploitable SQLi.

### 14. Full Chaos Mode
```bash
./sqli-hunter.sh -d http://verily.com -m -v -w -r -S -x -y
```
- **What**: Multi-scan with all bells and whistles.
- **Output**: `XSS Hits: 2 ... Report saved ...`
- **Why**: Go all-in.

### 15. Multi-Target List
```bash
echo -e "http://example.com\nhttp://testphp.vulnweb.com\nhttp://verily.com" > targets.txt
./sqli-hunter.sh -l targets.txt -m -r
```
- **What**: Multi-scan each domain in `targets.txt`.
- **Output**: `Summary for example.com ... Summary for testphp.vulnweb.com ...`
- **Why**: Batch bug hunting.

---

## Output Structure
Results land in `./Recon/<domain>/`:
- `urls/`: Crawled URLs (`katana_urls.txt`, `waymore_urls.txt`, `total_urls.txt`).
- `parameters/`: Extracted params (`params.txt`).
- `Vuln/`: Vuln hits (`blind_bool.txt`, `xss.txt`, etc.) + `sqlmap_results/`.
- `secrets/`: Leaked goodies (`sensitive_pdfs.txt`, `api_keys.txt`, etc.).
- `report.txt`: Summary (if `-r` used).

---

## Troubleshooting
- **Tool Missing**: Run `-t` to diagnose—install missing tools and check `PATH` with `which <tool>`.
- **DalFox Fails**: Ensure `go install` worked—`dalfox --version` should respond.
- **Permission Issues**: `chmod +x sqli-hunter.sh`.
- **Tor Errors**: Verify `torsocks` and Tor service are running for `-S`.

---

## Contributing
Got ideas? Smash issues or PRs into [sqli-hunter](https://github.com/manojxshrestha/sqli-hunter). Let’s make it nastier!

---

## Sample Run
```
┌──(pwn㉿aparichit)-[~]
└─$ ./sqli-hunter.sh -t

   _________      .__  .__            ___ ___               __
  /   _____/ _____|  | |__|          /   |   \ __ __  _____/  |_  ___________
  \_____  \ / ____/  | |  |  ______ /    ~    \  |  \/    \   __\/ __ \_  __ \
  /        < <_|  |  |_|  | /_____/ \    Y    /  |  /   |  \  | \  ___/|  | \/
 /_______  /\__   |____/__|          \___|_  /|____/|___|  /__|  \___  >__|
         \/    |__|                        \/            \/          \/

 SQLi Hunter v1.0 - by manojxshrestha

[2025-03-14 13:18:16] Checking tools...
  [+] subfinder - Found at /home/pwn/go/bin/subfinder
  [+] curl - Found at /usr/bin/curl
  [+] jq - Found at /usr/bin/jq
  [+] waymore - Found at /usr/bin/waymore
  [+] katana - Found at /home/pwn/go/bin/katana
  [+] httpx - Found at /home/pwn/go/bin/httpx
  [+] gf - Found at /home/pwn/go/bin/gf
  [+] uro - Found at /home/pwn/.local/bin/uro
  [+] qsreplace - Found at /home/pwn/go/bin/qsreplace
  [+] sqlmap - Found at /usr/local/bin/sqlmap
  [+] anew - Found at /home/pwn/go/bin/anew
  [+] dalfox - Found at /home/pwn/go/bin/dalfox
  [+] pdftotext - Found (optional)
  [+] torsocks - Found (optional)
  [i] crt.sh - Using curl + jq for https://crt.sh
[2025-03-15 13:18:17] All core tools ready!
```

Happy Hunting! 🧑🏻‍💻
