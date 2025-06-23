from flask import Flask, request, render_template
from supabase import create_client
import os
from datetime import datetime
import requests
import socket
import re
import ipaddress 

app = Flask(__name__)

# Supabase config
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Supabase URL and Key must be set as environment variables.")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Trap pages to log
TRAP_PAGES = {
    '/access-form.html',
    '/do-not-visit.html',
    '/robots-only.html'
}

# Load well-known bots from GitHub (using full schema)
try:
    WELL_KNOWN_BOTS_URL = "https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json"
    resp = requests.get(WELL_KNOWN_BOTS_URL)
    if resp.status_code == 200:
        parsed = resp.json()
        if isinstance(parsed, list):
            WELL_KNOWN_BOTS = parsed
        else:
            WELL_KNOWN_BOTS = []
    else:
        WELL_KNOWN_BOTS = []
except Exception as e:
    print("[-] Failed to load well-known bots list:", e)
    WELL_KNOWN_BOTS = []

# Lookup IP info from IPinfo API
def ipinfo_lookup(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print("[-] IPinfo lookup failed:", e)
    return {}

# Check if IPinfo tags this IP as a crawler
def is_crawler_tag(ip):
    try:
        url = f"https://ipinfo.io/{ip}/tags?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=5)
        if resp.ok:
            tags = resp.json()
            return "crawler" in tags
    except Exception as e:
        print("[-] Crawler tag check failed:", e)
    return False

# Reverse DNS check for a set of patterns
def reverse_dns_matches(ip, masks):
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        for mask in masks:
            pattern = mask.replace("*", r"[\w-]+")
            if re.fullmatch(pattern.replace(".", r"\."), hostname):
                return True
    except Exception:
        pass
    return False

# Main spoof detection logic using IPinfo and GitHub bot list
def validate_bot(ip, ua, ipinfo_data):
    ua_lc = ua.lower()
    as_org = ipinfo_data.get("org", "").lower()
    crawler_tagged = is_crawler_tag(ip)

    for bot in WELL_KNOWN_BOTS:
        bot_id = bot.get("id", "")
        patterns = bot.get("pattern", {}).get("accepted", [])
        org_aliases = bot.get("categories", [])
        verifications = bot.get("verification", [])

        ua_match = any(re.search(p, ua) for p in patterns)
        dns_masks = []

        for ver in verifications:
            if ver.get("type") == "dns":
                dns_masks.extend(ver.get("masks", []))

        dns_match = reverse_dns_matches(ip, dns_masks)
        org_match = any(alias in as_org for alias in org_aliases)

        if ua_match and dns_match and org_match and crawler_tagged:
            return {
                "bot": bot_id,
                "is_spoofed": False,
                "domain_match": dns_match,
                "org_match": org_match
            }

    return {
        "bot": None,
        "is_spoofed": True,
        "domain_match": False,
        "org_match": False
    }

# New helper functions to extract single client IP from headers
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def get_client_ip(headers, remote_addr):
    x_forwarded_for = headers.get("X-Forwarded-For", "")
    ip_list = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]

    for ip in ip_list:
        if not is_private_ip(ip):
            return ip
    return ip_list[0] if ip_list else remote_addr

# Log to Supabase only if it's a trap page
def log_to_supabase(req):
    try:
        path = req.path
        if path not in TRAP_PAGES:
            return

        ip = get_client_ip(req.headers, req.remote_addr)  # <-- use new function here
        ua = req.headers.get("User-Agent", "")
        headers = dict(req.headers)
        raw = f"{req.method} {req.full_path}"

        ipinfo_data = ipinfo_lookup(ip)
        crawler_tagged = is_crawler_tag(ip)
        spoof_check = validate_bot(ip, ua, ipinfo_data)

        score = 100
        if spoof_check["is_spoofed"]:
            score -= 70
        if not crawler_tagged:
            score -= 30

        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip,
            "user_agent": ua,
            "headers": headers,
            "path": path,
            "raw_request": raw,
            "ipinfo": ipinfo_data,
            "is_crawler": crawler_tagged,
            "spoof_check": spoof_check,
            "confidence_score": score
        }

        supabase.table("honeypot_logs").insert(data).execute()
        print("[+] Logged to Supabase:", data)

    except Exception as e:
        print("[-] Logging failed:", e)

@app.route('/')
def serve_index():
    return render_template('index.html')

@app.route('/<page>')
def serve_html_pages(page):
    page_path = f'/{page}'
    if page.endswith('.html') and os.path.exists(f'templates/{page}'):
        log_to_supabase(request)
        return render_template(page)
    return 'Page not found', 404

@app.route('/log', methods=['GET', 'POST'])
def log_only():
    log_to_supabase(request)
    return 'OK', 200

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return "<h1>Welcome</h1><p>This is a honeypot page.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
