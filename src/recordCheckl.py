import json
import re
import requests
from urllib.parse import urljoin

SITE_URL = "https://orgfarm-5e0a893263-dev-ed.develop.my.site.com/aflabs"
LWR_ENDPOINT = f"{SITE_URL}/webruntime/api/apex/execute"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cybersecurity-Audit/1.0",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Regex pattern for @salesforce/apex imports
APEX_IMPORT_REGEX = re.compile(
    r'@salesforce/apex/(?:([a-zA-Z0-9_]+)\.)?([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)'
)

def extract_js_urls(html_content, base_url):
    """Parses script src attributes from the HTML source."""
    script_srcs = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html_content, re.IGNORECASE)
    return {urljoin(base_url, src) for src in script_srcs}

def scan_js_for_endpoints(js_url):
    """Extracts Apex controller and method names from a single JS file."""
    discovered = set()
    try:
        res = requests.get(js_url, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            matches = APEX_IMPORT_REGEX.findall(res.text)
            for ns, classname, method in matches:
                discovered.add((ns, classname, method))
            
            # Additional pattern for minified controller references
            compiled_matches = re.findall(r'["\']([a-zA-Z0-9_]+Controller)\.([a-zA-Z0-9_]+)["\']', res.text)
            for classname, method in compiled_matches:
                discovered.add(("", classname, method))
    except requests.RequestException:
        pass
    return discovered

def test_apex_execution(namespace, classname, method, params=None):
    """Executes a discovered method against the LWR endpoint and inspects return values."""
    if params is None:
        params = {}

    payload = {
        "namespace": namespace,
        "classname": classname,
        "method": method,
        "params": params
    }

    print(f"\n[*] Testing Apex Action: {classname}.{method}")
    try:
        res = requests.post(LWR_ENDPOINT, json=payload, headers=HEADERS, timeout=10)
        print(f"    Status Code: {res.status_code}")

        if res.status_code == 200:
            try:
                data = res.json()
                print(f"    [!] EXPOSED ENDPOINT / SUCCESSFUL RESPONSE:")
                print(f"    Return Value: {json.dumps(data, indent=6)}")
            except json.JSONDecodeError:
                print("    [!] HTTP 200 returned non-JSON body.")
        elif res.status_code in (401, 403):
            print(f"    [*] Access Denied (HTTP {res.status_code}) — Properly secured.")
        else:
            print(f"    [-] Server error or unhandled code: HTTP {res.status_code}")

    except requests.RequestException as e:
        print(f"    [-] Connection error: {e}")

def run_pipeline():
    print("=====================================================")
    print(" Salesforce LWR Apex Discovery & Audit Pipeline ")
    print("=====================================================")

    print(f"[*] Accessing target: {SITE_URL}")
    try:
        homepage = requests.get(SITE_URL, headers=HEADERS, timeout=10)
        if homepage.status_code != 200:
            print(f"[-] Could not reach homepage (HTTP {homepage.status_code}).")
            return

        js_urls = extract_js_urls(homepage.text, SITE_URL)
        print(f"[+] Found {len(js_urls)} script references on homepage.")

        all_endpoints = set()
        for js_url in js_urls:
            print(f"[*] Parsing: {js_url.split('/')[-1]}")
            endpoints = scan_js_for_endpoints(js_url)
            all_endpoints.update(endpoints)

        if not all_endpoints:
            print("[-] No explicit Apex class/method endpoints detected in homepage scripts.")
            return

        print(f"\n[+] Discovered {len(all_endpoints)} candidate methods. Beginning verification sweep...")
        
        for ns, classname, method in all_endpoints:
            test_apex_execution(ns, classname, method)

    except requests.RequestException as e:
        print(f"[-] Execution stopped due to error: {e}")

if __name__ == "__main__":
    run_pipeline()