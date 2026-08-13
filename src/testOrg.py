import json
import re
import requests
from urllib.parse import urljoin

# Set the target Salesforce Experience Cloud URL
TARGET_URL = "https://orgfarm-5e0a893263-dev-ed.develop.my.site.com/aflabs"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cybersecurity-Audit/1.0",
    "Accept": "application/json, text/plain, */*"
}

def log(status, message):
    symbols = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "FAIL": "[-]"}
    print(f"{symbols.get(status, '[*]')} {message}")

def check_site_availability(base_url):
    """Verifies that the target URL is reachable."""
    log("INFO", f"Checking site availability: {base_url}")
    try:
        res = requests.get(base_url, headers=HEADERS, timeout=10)
        log("OK", f"Site responded with HTTP status code {res.status_code}")
        return res
    except requests.RequestException as e:
        log("FAIL", f"Could not reach target URL: {e}")
        return None

def audit_aura_endpoint(base_url):
    """Tests the /aura endpoint for guest accessibility and framework leaks."""
    log("INFO", "Auditing Aura Framework endpoint...")
    aura_url = urljoin(base_url, "/s/sfsites/aura")
    
    # Simple handshake/descriptor request
    payload = {
        "message": json.dumps({
            "actions": [{
                "id": "1;a",
                "descriptor": "aura://ComponentController/ACTION$getComponent",
                "callingDescriptor": "UNKNOWN",
                "params": {
                    "name": "markup://c:default"
                }
            }]
        })
    }
    
    try:
        res = requests.post(aura_url, data=payload, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            log("WARN", f"Aura endpoint accessible at {aura_url} (HTTP 200)")
            if "aura:invalidSession" in res.text:
                log("INFO", "Aura endpoint requires valid session (Good)")
            else:
                log("WARN", "Aura endpoint responded without session error. Check for exposed actions.")
        else:
            log("INFO", f"Aura endpoint returned HTTP {res.status_code}")
    except requests.RequestException as e:
        log("FAIL", f"Failed to audit Aura endpoint: {e}")

def check_sensitive_endpoints(base_url):
    """Checks common public endpoints for exposed metadata or configurations."""
    log("INFO", "Checking common public configuration paths...")
    paths_to_check = [
        "/s/login/",
        "/s/selfregister",
        "/s/.well-known/openid-configuration",
        "/login/",
        "/selfregister",
        "/.well-known/openid-configuration",
        "/services/apexrest/",
        "/sfsites/c/fileFetch.app",
        "/servlet/servlet.FileDownload"
    ]
    
    for path in paths_to_check:
        full_url = urljoin(base_url, path)
        try:
            res = requests.get(full_url, headers=HEADERS, timeout=7)
            if res.status_code == 200:
                log("WARN", f"Accessible path found (HTTP 200): {full_url}")
            elif res.status_code in [301, 302]:
                log("INFO", f"Redirected path (HTTP {res.status_code}): {path}")
            else:
                log("INFO", f"Path {path} returned HTTP {res.status_code}")
        except requests.RequestException:
            log("FAIL", f"Timeout or error requesting {path}")

def scan_javascript_for_controllers(response):
    """Parses JavaScript bundles to extract exposed Aura/LWC controllers and actions."""
    log("INFO", "Scanning homepage JavaScript bundles for controller definitions...")
    if not response or not response.text:
        return

    # Extract script src tags
    script_urls = re.findall(r'src=["\'](.*?\.(?:js|app))["\']', response.text)
    log("INFO", f"Found {len(script_urls)} external scripts in homepage source.")
    
    action_pattern = re.compile(r'@AuraEnabled|c:[a-zA-Z0-9_]+Controller|\b[a-zA-Z0-9_]+Controller\.[a-zA-Z0-9_]+\b')
    
    found_controllers = set()
    for script_rel in script_urls[:5]:  # Limit scan to first 5 core scripts
        script_url = urljoin(TARGET_URL, script_rel)
        try:
            res = requests.get(script_url, headers=HEADERS, timeout=10)
            if res.status_code == 200:
                matches = action_pattern.findall(res.text)
                for match in matches:
                    found_controllers.add(match)
        except requests.RequestException:
            continue
            
    if found_controllers:
        log("WARN", f"Potential controller/action references discovered: {list(found_controllers)[:10]}")
    else:
        log("INFO", "No explicit controller signatures detected in initial JS bundles.")

def run_audit():
    print("==================================================")
    print(" Salesforce Experience Cloud Security Audit Tool ")
    print("==================================================")
    
    res = check_site_availability(TARGET_URL)
    if res:
        check_sensitive_endpoints(TARGET_URL)
        audit_aura_endpoint(TARGET_URL)
        scan_javascript_for_controllers(res)
        
    print("\n[+] Audit sweep completed.")

if __name__ == "__main__":
    run_audit()