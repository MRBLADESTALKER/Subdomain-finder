#!/usr/bin/env python3
import requests
import argparse
import concurrent.futures
from colorama import Fore, Style, init
import sys
import json
import socket
import os
from tqdm import tqdm  # For progress bar
import time
import logging

# Init colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------- Banner ----------
def banner():
    print(Fore.RED + r"""
██████╗ ██╗      █████╗ ██████╗ ███████╗██╗  ██╗
██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██████╔╝██║     ███████║██████╔╝█████╗  █████╔╝ 
██╔═══╝ ██║     ██╔══██║██╔══██╗██╔══╝  ██╔═██╗ 
██║     ███████╗██║  ██║██║  ██║███████╗██║  ██╗
╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """)
    print(Fore.RED + "       Code by Bladex (Improved Version)")
    print(Fore.RED + "       Telegram: @mrbladestalker0093\n" + Style.RESET_ALL)

# ---------- Sources ----------
SOURCES = {
    "crtsh": "https://crt.sh/?q=%25.{domain}&output=json",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "sonar": "https://sonar.omnisint.io/subdomains/{domain}",
    "rapiddns": "https://rapiddns.io/subdomain/{domain}?full=1",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "securitytrails": "https://api.securitytrails.com/v1/domain/{domain}/subdomains",  # Requires API key
    "virustotal": "https://www.virustotal.com/vtapi/v2/domain/report?apikey={apikey}&domain={domain}",  # Requires API key
}

# ---------- Functions ----------
def fetch_url(url, timeout=10, retries=3):
    """Generic fetch function with retries."""
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                return r
            else:
                logging.warning(f"Failed to fetch {url} (status: {r.status_code}), retrying...")
                time.sleep(1)
        except Exception as e:
            logging.error(f"Error fetching {url}: {e}")
            time.sleep(1)
    return None

def fetch_crtsh(domain):
    url = SOURCES["crtsh"].format(domain=domain)
    r = fetch_url(url)
    if r:
        try:
            return [entry["name_value"] for entry in r.json()]
        except json.JSONDecodeError:
            return []
    return []

def fetch_hackertarget(domain):
    url = SOURCES["hackertarget"].format(domain=domain)
    r = fetch_url(url)
    if r:
        return [line.split(",")[0] for line in r.text.splitlines() if line]
    return []

def fetch_sonar(domain):
    url = SOURCES["sonar"].format(domain=domain)
    r = fetch_url(url)
    if r:
        try:
            data = r.json()
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []
    return []

def fetch_rapiddns(domain):
    url = SOURCES["rapiddns"].format(domain=domain)
    r = fetch_url(url)
    if r:
        subdomains = []
        lines = r.text.split("\n")
        for line in lines:
            if domain in line and "<td>" in line:
                try:
                    sub = line.split("<td>")[1].split("</td>")[0].strip()
                    if sub:
                        subdomains.append(sub)
                except IndexError:
                    continue
        return subdomains
    return []

def fetch_alienvault(domain):
    url = SOURCES["alienvault"].format(domain=domain)
    r = fetch_url(url)
    if r:
        try:
            data = r.json().get("passive_dns", [])
            return [entry["hostname"] for entry in data if "hostname" in entry]
        except json.JSONDecodeError:
            return []
    return []

def fetch_securitytrails(domain, api_key=None):
    if not api_key:
        logging.warning("SecurityTrails requires API key. Skipping.")
        return []
    url = SOURCES["securitytrails"].format(domain=domain)
    headers = {"APIKEY": api_key}
    r = fetch_url(url, headers=headers)
    if r:
        try:
            data = r.json().get("subdomains", [])
            return [sub + "." + domain for sub in data]
        except json.JSONDecodeError:
            return []
    return []

def fetch_virustotal(domain, api_key=None):
    if not api_key:
        logging.warning("VirusTotal requires API key. Skipping.")
        return []
    url = SOURCES["virustotal"].format(apikey=api_key, domain=domain)
    r = fetch_url(url)
    if r:
        try:
            data = r.json().get("subdomains", [])
            return data
        except json.JSONDecodeError:
            return []
    return []

# ---------- Validate ----------
def validate_subdomain(subdomain, check_dns=False, check_http=False, check_https=False, timeout=3):
    if check_dns:
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
    if check_http:
        try:
            requests.get(f"http://{subdomain}", timeout=timeout)
            return True
        except:
            pass
    if check_https:
        try:
            requests.get(f"https://{subdomain}", timeout=timeout)
            return True
        except:
            pass
    return False

# ---------- Save to File ----------
def save_to_file(subdomains, filename):
    try:
        with open(filename, 'w') as f:
            for sub in subdomains:
                f.write(sub + '\n')
        logging.info(f"Results saved to {filename}")
    except Exception asNavigate e:
        logging.error(f"Error saving to file: {e}")

# ---------- Main ----------
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="🔥 Bladex Advanced Subdomain Finder (Improved CLI Tool) 🔥",
        usage="python bladex_subfinder.py -d example.com [--threads 100] [--with-links] [--output output.txt] [--api-key KEY] [--validate-dns] [--validate-https] [--sources all]"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--threads", type=int, default=50, help="Max threads for validation (default 50, max 200)")
    parser.add_argument("--with-links", action="store_true", help="Show subdomains with http/https links")
    parser.add_argument("--output", help="Output file to save results")
    parser.add_argument("--api-key", help="API key for services like SecurityTrails and VirusTotal")
    parser.add_argument("--validate-dns", action="store_true", help="Validate by DNS resolution instead of HTTP")
    parser.add_argument("--validate-https", action="store_true", help="Validate by HTTPS request (in addition to HTTP)")
    parser.add_argument("--sources", default="default", help="Sources to use: 'default', 'all' (default uses basic sources)")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries for fetching sources")
    args = parser.parse_args()

    if args.threads > 200:
        print(Fore.YELLOW + "[!] Max threads is 200. Setting to 200.")
        args.threads = 200

    domain = args.domain.strip().lower()
    print(Fore.CYAN + f"[*] Finding subdomains for: {domain}")

    all_subdomains = set()

    # Collect subdomains from sources
    fetch_functions = {
        "crtsh": fetch_crtsh,
        "hackertarget": fetch_hackertarget,
        "sonar": fetch_sonar,
        "rapiddns": fetch_rapiddns,
    }
    if args.sources == "all":
        fetch_functions.update({
            "alienvault": fetch_alienvault,
            "securitytrails": lambda d: fetch_securitytrails(d, args.api_key),
            "virustotal": lambda d: fetch_virustotal(d, args.api_key),
        })

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_source = {executor.submit(func, domain): name for name, func in fetch_functions.items()}
        for future in concurrent.futures.as_completed(future_to_source):
            name = future_to_source[future]
            try:
                subs = future.result()
                all_subdomains.update(subs)
                logging.info(f"Fetched {len(subs)} from {name}")
            except Exception as e:
                logging.error(f"Error in {name}: {e}")

    # Clean subdomains
    subdomains = [s.strip().lower() for s in all_subdomains if domain in s and s.endswith(domain)]
    subdomains = list(set(subdomains))  # Remove duplicates

    print(Fore.CYAN + f"[*] Total unique subdomains found: {len(subdomains)}")

    if subdomains:
        print(Fore.CYAN + f"[*] Validating with {args.threads} threads...")

        valid_subs = []
        validation_func = lambda sub: validate_subdomain(
            sub,
            check_dns=args.validate_dns,
            check_http=not args.validate_dns,
            check_https=args.validate_https,
            timeout=3
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            results = list(tqdm(executor.map(validation_func, subdomains), total=len(subdomains), desc="Validating"))

        valid_subs = [sub for sub, is_valid in zip(subdomains, results) if is_valid]

        print(Fore.GREEN + f"[+] Alive/Valid subdomains: {len(valid_subs)}\n")

        # Print results
        output_list = valid_subs
        if args.with_links:
            for sub in sorted(output_list):
                print(f"http://{sub}")
                print(f"https://{sub}")
        else:
            for sub in sorted(output_list):
                print(sub)

        # Save to file if specified
        if args.output:
            save_to_file(output_list, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
