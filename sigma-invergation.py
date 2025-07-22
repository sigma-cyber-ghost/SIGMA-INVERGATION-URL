#!/usr/bin/env python3
import os, socket, requests, whois, re, time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from ipwhois import IPWhois
from colorama import init, Fore, Style

init(autoreset=True)

# ======= BANNER =======
def show_banner():
    banner = r'''
⠉⠉⠉⠉⠁⠀⠀⠀⠀⠒⠂⠰⠤⢤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠻⢤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠠⠀⠐⠒⠒⠀⠀⠈⠉⠉⠉⠉⢉⣉⣉⣉⣙⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡀⠤⠒⠒⠉⠁⠀⠀⠀⠀⠳⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⠛⠛⠉⠛⠛⠶⢦⣤⡐⢀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠈⠉⢳⣦⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠳⡤⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠛⠳⠶⢶⣦⠤⣄⡀⠀⠀⠀

=========== SIGMA-CYBER-GHOST ===========
🐦 Twitter:   https://twitter.com/safderkhan0800
💬 Telegram:  https://t.me/Sigma_Cyber_Ghost
📺 YouTube:   https://www.youtube.com/@sigma_ghost_hacking
💻 GitHub:    https://github.com/sigma-cyber-ghost
-----------------------------------------
'''
    print(Fore.RED + banner)

# ======= MALWARE & IMPLANT DETECTION =======
def detect_malware(content, url):
    findings = []
    if 'document.write' in content or 'eval(' in content or 'setTimeout' in content:
        findings.append("⚠️ Obfuscated JavaScript detected")
    if 'base64' in content:
        findings.append("⚠️ Base64-encoded payload found")
    if '<iframe' in content:
        findings.append("⚠️ Suspicious iFrame found")
    if re.search(r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|fb\.me)", url):
        findings.append("⚠️ Shortened/redirecting link detected")
    if '.onion' in url or '.onion' in content:
        findings.append("⚠️ Dark Web Onion link detected")
    if re.search(r"(keylogger|onkeydown=|logkeys|fetch\(|new Image\()", content):
        findings.append("⚠️ Possible keylogger/injection detected")
    if any(x in url for x in ['fbclid', 'utm_', 'ref=']):
        findings.append("⚠️ Tracking/Referrer tags detected")
    return findings or ["✓ No known malicious patterns detected."]

# ======= URL BEHAVIOR EMULATION =======
def emulate_click_behavior(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        return r.url, r.history, r.text
    except:
        return url, [], ""

# ======= CORE FUNCTIONS =======
def resolve_ip(url):
    domain = urlparse(url).netloc
    try: ip = socket.gethostbyname(domain)
    except: ip = "Failed"
    return domain, ip

def whois_lookup(domain):
    try: return whois.whois(domain)
    except: return "WHOIS failed."

def reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return "N/A"

def geo_trace(ip):
    try:
        obj = IPWhois(ip)
        return obj.lookup_rdap()
    except:
        return "GeoIP lookup failed."

def extract_metadata(content):
    try:
        soup = BeautifulSoup(content, 'html.parser')
        return {
            "title": soup.title.string if soup.title else "None",
            "scripts": [s.get('src') for s in soup.find_all('script') if s.get('src')],
            "metas": [m.get('content') for m in soup.find_all('meta') if m.get('content')]
        }
    except:
        return {"error": "Metadata extraction failed"}

def extract_query_params(url):
    try:
        q = urlparse(url).query
        return parse_qs(q)
    except:
        return {}

# ======= FINAL SCAN ENGINE =======
def scan(url):
    show_banner()
    print(Fore.CYAN + f"\n[+] Target URL: {url}")
    
    final_url, redirects, content = emulate_click_behavior(url)

    print(Fore.YELLOW + "\n[•] Redirect chain:")
    if redirects:
        for step in redirects:
            print("→", step.url)
    print(Fore.GREEN + f"=> Final URL: {final_url}")

    print(Fore.YELLOW + "\n[•] Analyzing content for malware & implants...")
    for result in detect_malware(content.lower(), final_url):
        print(Fore.RED + ">> " + result)

    print(Fore.YELLOW + "\n[•] DNS/IP/Ownership:")
    domain, ip = resolve_ip(final_url)
    print("Domain:", domain)
    print("IP:", ip)
    print("WHOIS:", whois_lookup(domain))
    print("Reverse DNS:", reverse_dns(ip))

    print(Fore.YELLOW + "\n[•] ASN / Geo Trace:")
    print(geo_trace(ip))

    print(Fore.YELLOW + "\n[•] Extracting metadata...")
    meta = extract_metadata(content)
    for key, value in meta.items():
        print(f"{key}: {value}")

    print(Fore.YELLOW + "\n[•] URL Parameters / Trackers:")
    params = extract_query_params(final_url)
    if params:
        for k, v in params.items():
            print(f"{k}: {v}")
    else:
        print("No query parameters found.")

    print(Fore.GREEN + "\n[✓] SIGMA-TRACE OMNISIGHT FINISHED.")

# ======= ENTRY =======
if __name__ == "__main__":
    try:
        os.system("clear")
    except:
        pass
    u = input(Fore.CYAN + "[+] Enter URL to analyze: ").strip()
    scan(u)
