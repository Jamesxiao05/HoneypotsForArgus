# Import all necessary libraries such as requests to get IP info, Flask for the web server, and Supabase for logging.
import requests
import ipaddress
import socket
import re
import json
import os
from typing import List, Dict, Set, Tuple
from flask import Flask, request, render_template
from supabase import create_client
from datetime import datetime

# App & Supabase configuration with keys from environment variables
app = Flask(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

# Ensure all required environment variables are set otherwise don't run the app
if not all([SUPABASE_URL, SUPABASE_KEY, IPINFO_TOKEN]):
    raise ValueError(
        "SUPABASE_URL, SUPABASE_KEY, and IPINFO_TOKEN must be set as environment variables."
    )

# Get the supabase client keys
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Define what the honeypot trap pages are and what tokens are generic and not useful for bot detection; can be filtered out when parsing user agents.
TRAP_PAGES = {'/access-form.html', '/do-not-visit.html', '/robots-only.html'}
GENERIC_TOKENS = {
    'mozilla', 'windows', 'linux', 'android', 'applewebkit', 'chrome',
    'safari', 'firefox', 'mobile', 'gecko', 'intel', 'macintosh', 'rv', 'nt',
    'win64', 'x64', 'like', 'khtml', 'compatible', 'version'
}

# Load the well-known bots list from the GitHub repositry and start to parse through it. Give back an error if it fails to load.
WELL_KNOWN_BOTS = []
try:
    WELL_KNOWN_BOTS_URL = "https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json"
    resp = requests.get(WELL_KNOWN_BOTS_URL)
    if (resp.status_code >= 200) and (resp.status_code < 300):
        parsed = resp.json()
        WELL_KNOWN_BOTS = parsed if isinstance(parsed, list) else []
    else:
        print(
            f"[-] Failed to load well-known bots list, status code: {resp.status_code}"
        )
except Exception as e:
    print(f"[-] Failed to load well-known bots list: {e}")


def _get_values_from_json(data: Dict, path: str) -> List[str]:
    '''These are just helper functions used to help parse through the JSON file and get specific values from it. These are             later used in our IP verification functions like the DNS and CIDR verification functions. Specifically, it finds things         like prefixes, ipv4Prefix, and ipv6Prefix. This is focusing on the instance/user agent for this function.
    '''
    try:
        # Match the specific pattern: $.key[*] or $.key[*]['subkey1','subkey2']
        match = re.match(r"\$\.(\w+)\[\*\](.*)", path)
        if not match:
            return []

        key, remaining_path = match.groups()

        # Get the initial list from the data
        if not isinstance(data, dict) or key not in data:
            return []
        list_data = data[key]
        if not isinstance(list_data, list):
            return []

        # If there's no sub-key selection, can't do anything
        if not remaining_path:
            return []

        # Handle the subkey selection like the ipv4 and ipv6 prefixes
        # Replace escaped quotes and find all keys within the brackets
        sub_keys_str = remaining_path.replace('"', "'").strip("[]")
        sub_keys = [k.strip().strip("'") for k in sub_keys_str.split(',')]

        values = []
        for item in list_data:
            if isinstance(item, dict):
                for sub_key in sub_keys:
                    if sub_key in item:
                        values.append(item[sub_key])
        return values

    # Throw an exception if it fails to parse the JSONPath
    except Exception as e:
        print(f"[!!!] Failed to parse JSONPath '{path}': {e}")
        return []


def _fetch_json_from_url(url):
    '''Get the urls from the JSON file and parse through them properly. Timeout after so that it doesn't hang indefinitely.
    '''
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Could not fetch JSON from {url}: {e}")
        return None


def ipinfo_lookup(ip_address: str):
    '''Use IPinfo to get the IP address of the client.
    '''
    url = f"https://ipinfo.io/{ip_address}?token={IPINFO_TOKEN}"
    return _fetch_json_from_url(url)


def get_client_ip(headers, remote_addr):
    '''Get the client IP address from the headers or the remote address.
    '''
    x_forwarded_for = headers.get("X-Forwarded-For", "")
    if x_forwarded_for:
        # The first IP in the list is the original client IP. Could fail if user is using a proxy or VPN.
        return x_forwarded_for.split(',')[0].strip()
    return remote_addr


def verify_cidr(ip_address: str, bot_id: str) -> bool:
    '''Go with a CIDR verification function to verify the IP address of the client and see if it matches the CIDR block of the         bot. This is the most reliable way to verify a bot because it checks the IP address directly.
    '''
    bot_data = next(
        (bot for bot in WELL_KNOWN_BOTS if bot.get("id") == bot_id), None)
    if not bot_data: return False
    cidr_verification_data = next(
        (v
         for v in bot_data.get("verification", []) if v.get("type") == "cidr"),
        None)
    if not cidr_verification_data: return False
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    sources = cidr_verification_data.get("sources", [])
    for source in sources:
        if source.get("type") == "http-json":
            url, selector = source.get("url"), source.get("selector")
            if not all([url, selector]): continue
            remote_data = _fetch_json_from_url(url)
            if not remote_data: continue
            cidr_list = _get_values_from_json(remote_data, selector)
            for cidr_str in cidr_list:
                try:
                    if cidr_str and ip_obj in ipaddress.ip_network(
                            cidr_str, strict=False):
                        return True
                except ValueError:
                    continue
    return False


def verify_dns(ip_address: str, bot_id: str) -> bool:
    '''Create a DNS verification function to verify the IP address of the client and see if it matches the DNS record of the           bot. This is less reliable than the CIDR verification function because it relies on the DNS record of the bot.
    '''
    bot_data = next(
        (bot for bot in WELL_KNOWN_BOTS if bot.get("id") == bot_id), None)
    if not bot_data: return False
    dns_verification_data = next(
        (v
         for v in bot_data.get("verification", []) if v.get("type") == "dns"),
        None)
    if not dns_verification_data: return False
    masks = dns_verification_data.get("masks", [])
    if not masks: return False
    ip_info = ipinfo_lookup(ip_address)
    if not ip_info: return False
    as_domain = ip_info.get("as_domain", "").lower()
    if not as_domain: return False
    for mask in masks:
        match = re.search(r'([\w.-]+)', mask.replace('***', ''))
        if not match: continue
        mask_domain_parts = match.group(1).split('.')
        if len(mask_domain_parts) < 2: continue
        owner_keyword = mask_domain_parts[-2]
        if owner_keyword in as_domain:
            return True
    return False


def parse_ua_components(ua: str) -> Dict[str, Set[str]]:
    '''This is a back-up test that is run if there is no CIDR or DNS verification data for the bot. It parses the user agent           string and compares it to the known user agent strings for the bot. This is less reliable than the CIDR and DNS                 verification functions because it relies on the user agent string of the bot only. It is also more computationally              expensive than the other two functions. Creates a tokenizer that breaks apart and assigns each part of the user agent a         token.
    '''
    ua_lower = ua.lower()
    parsed = {
        'products': set(re.findall(r'[\w\-]+/\d+(?:\.\d+)*', ua_lower)),
        'urls': set(re.findall(r'https?://[^\s;()]+', ua_lower)),
    }
    parsed['domains'] = {
        re.sub(r'^https?://(www\.)?', '', u).split('/')[0]
        for u in parsed['urls']
    }
    candidate_tokens = re.findall(r'[\w\-\.]{4,}', ua_lower)
    parsed['tokens'] = {
        token.strip('.-')
        for token in candidate_tokens
        if token.strip('.-') not in GENERIC_TOKENS
    }
    return parsed


def compute_advanced_match_score(test_fp: Dict[str, Set[str]],
                                 known_fp: Dict[str, Set[str]]) -> float:
    '''Create a math function that uses discrete mathematical logic to assign each token a weight based on importance and how          many times it appears in the user agent string. The intersection and union of the sets of tokens are used to calculate          the similarity between the user agent strings.
    '''
    weights = {'products': 0.5, 'urls': 0.4, 'domains': 0.4, 'tokens': 0.2}
    score = 0.0
    for field, weight in weights.items():
        s1, s2 = test_fp.get(field, set()), known_fp.get(field, set())
        if s1 and s2:
            ratio = len(s1 & s2) / len(s1 | s2)
            score += weight * ratio
    total_weight = sum(weights.values())
    return score / total_weight if total_weight else 0.0


def is_same_entity_ua(test_ua: str,
                      known_uas: List[str],
                      score_threshold: float = 0.6) -> bool:
    '''Create a function that uses the above functions to determine if the user agent string of the client matches the known           user agent strings for the bot by matching it against a threshold score of 0.6.
    '''
    if not known_uas: return False
    test_fp = parse_ua_components(test_ua)
    for known_ua in known_uas:
        known_fp = parse_ua_components(known_ua)
        if compute_advanced_match_score(test_fp, known_fp) >= score_threshold:
            return True
    return False


def analyze_bot_request(ip_address: str, user_agent: str) -> Dict:
    """This is the heart of the bot detection system. It takes the IP address and user agent string of the client and uses the         above functions to determine if the client is a bot. It returns a dictionary with the status of the client, the ID of           the bot, and a result if it matches, and the reason for the decision.
    """
    for bot in WELL_KNOWN_BOTS:
        patterns = bot.get("pattern", {})
        accepted_patterns = patterns.get("accepted", [])
        forbidden_patterns = patterns.get("forbidden", [])
        ua_is_accepted = any(
            re.search(p, user_agent) for p in accepted_patterns)
        ua_is_forbidden = any(
            re.search(p, user_agent) for p in forbidden_patterns)
        if ua_is_accepted and not ua_is_forbidden:
            bot_id = bot.get("id")
            if bot.get("verification"):
                if verify_cidr(ip_address, bot_id) or verify_dns(
                        ip_address, bot_id):
                    return {
                        "status": "LEGITIMATE",
                        "bot_id": bot_id,
                        "reason": "IP verification passed."
                    }
                else:
                    return {
                        "status": "SPOOFED",
                        "bot_id": bot_id,
                        "reason": "IP verification failed."
                    }
            if bot.get("instances"):
                if is_same_entity_ua(user_agent,
                                     bot["instances"].get("rejected", [])):
                    return {
                        "status": "REJECTED",
                        "bot_id": bot_id,
                        "reason": "UA matched a rejected instance."
                    }
                if is_same_entity_ua(user_agent,
                                     bot["instances"].get("accepted", [])):
                    return {
                        "status": "LEGITIMATE",
                        "bot_id": bot_id,
                        "reason": "UA matched an accepted instance."
                    }
            return {
                "status": "UNVERIFIABLE",
                "bot_id": bot_id,
                "reason": "Pattern matched, no conclusive proof."
            }
    return {
        "status": "UNKNOWN",
        "bot_id": None,
        "reason": "UA did not match any known bot pattern."
    }


def log_to_supabase(req):
    """This is the core part of the logging system. It takes the request object and uses the above functions to determine if           the client is a bot and logs the result to the Supabase database. This is used to log ONLY the trap/honeypot pages              though.
    """
    try:
        ip = get_client_ip(req.headers, req.remote_addr)
        ua = req.headers.get("User-Agent", "")
        analysis_result = analyze_bot_request(ip, ua)
        data_to_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip,
            "port": req.environ.get("REMOTE_PORT"),
            "user_agent": ua,
            "headers": dict(req.headers),
            "path": req.path,
            "uri_query": req.query_string.decode(),
            "raw_request": f"{req.method} {req.full_path}",
            "ipinfo": ipinfo_lookup(ip),
            "analysis_result": analysis_result
        }
        response, count = supabase.table("honeypot_logs").insert(
            data_to_log).execute()
        print(
            f"[+] Logged to Supabase. Status: {analysis_result.get('status')}")
    except Exception as e:
        print(f"[!!!] Logging failed: {e}")


def log_regular_hit(req):
    """This is the second core part of the logging system. It takes the request object and uses the above functions to                 determine if the client is a bot and logs the result to the Supabase database. This is used to log everything this              time.
    """
    try:
        ip = get_client_ip(req.headers, req.remote_addr)
        ua = req.headers.get("User-Agent", "")
        data_to_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip,
            "user_agent": ua,
            "path": req.path,
        }
        supabase.table("regular_hits").insert(data_to_log).execute()
        print(f"[+] Logged regular hit for path: {req.path}")
    except Exception as e:
        print(f"[!!!] Regular logging failed: {e}")


# These are the flask routes that handle the requests to the server.
@app.route('/')
def serve_index():
    """
    Handles the homepage. This is never a trap page, so it only logs
    to the regular_hits table.
    """
    log_regular_hit(request)
    return render_template('index.html')


@app.route('/<path:page>')
def serve_pages(page):
    """
    Handles all other pages and decides where to log them.
    """
    # Check if the requested path is one of the trap pages
    if f"/{page}" in TRAP_PAGES:
        # If it's a trap page, run the full analysis and log to honeypot_logs
        log_to_supabase(request)
    else:
        # For any other page, log it as a simple hit to regular_hits
        log_regular_hit(request)

    # After logging, serve the content
    if page.endswith('.html') and os.path.exists(f'templates/{page}'):
        return render_template(page)

    return "<h1>Honeypot Page</h1><p>Thank you for your visit.</p>", 200


# Must be at the end of the file to run the app. Keep the port on 8080 which is used to communicate with Nginx and Gunicorn for public server hosting.
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
