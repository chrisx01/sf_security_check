#!/usr/bin/env python3
"""
sf_guest_audit.py
==================

Salesforce Guest-User / Unauthenticated REST API Exposure Auditor.

PURPOSE
-------
Guest User misconfigurations (over-permissive Guest User Profile,
Object/Field-Level Security, sharing rules, or exposed Apex REST
services on an Experience Cloud site) are a well-documented class of
Salesforce vulnerability that can lead to unauthenticated data
disclosure. This script helps you (the org owner / an authorized
tester) check whether standard and custom REST API endpoints are
readable:

  1. Fully unauthenticated (no session at all), and
  2. As an authenticated Guest User of your Experience Cloud site
     (if you supply a guest session id obtained legitimately).

It DOES NOT attempt to brute force, guess, or bypass authentication.
It only exercises documented REST API surfaces using credentials you
provide, to see what those credentials can see.

AUTHORIZATION
--------------
Only run this against a Salesforce org you own or have explicit
written authorization to test. Unauthorized access to computer
systems is illegal in most jurisdictions.

USAGE
-----
    pip install requests
    python sf_guest_audit.py --config config.json

OUTPUT
------
Console summary + a JSON report (path set in config) listing every
endpoint tested, the HTTP status returned, and a PASS/FLAG verdict for
each ("FLAG" = data was readable by an unauthenticated or guest
caller).
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("This script requires the 'requests' library: pip install requests")
    sys.exit(1)


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    category: str            # e.g. "sobject_describe", "sobject_query", "apex_rest"
    target: str               # object name or path tested
    caller: str                # "unauthenticated" | "guest_session"
    url: str
    method: str
    status_code: Optional[int]
    verdict: str               # "FLAG" | "PASS" | "ERROR"
    detail: str = ""
    sample: Any = None         # small redacted sample of returned data, if any


# --------------------------------------------------------------------------
# Auditor
# --------------------------------------------------------------------------

class SalesforceGuestAuditor:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config
        self.instance_url = config["instance_url"].rstrip("/")
        self.api_version = config.get("api_version", "60.0")
        self.timeout = config.get("timeout_seconds", 10)
        self.rate_delay = 1.0 / max(config.get("requests_per_second", 5), 0.1)
        self.row_limit = config.get("row_limit", 1)
        self.probe_fields = config.get("probe_fields", ["Id"])

        self.guest_session_id = config.get("guest_session_id") or None
        self.community_base_url = (config.get("community_base_url") or "").rstrip("/")

        self.findings: List[Finding] = []

    # ---- low level request helpers ----

    def _base_rest_url(self, path: str) -> str:
        return f"{self.instance_url}/services/data/v{self.api_version}{path}"

    def _headers(self, as_guest: bool) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if as_guest and self.guest_session_id:
            headers["Authorization"] = f"Bearer {self.guest_session_id}"
        return headers

    def _get(self, url: str, as_guest: bool) -> requests.Response:
        time.sleep(self.rate_delay)
        return requests.get(
            url,
            headers=self._headers(as_guest),
            timeout=self.timeout,
        )

    # ---- discovery ----

    def discover_objects(self, as_guest: bool) -> List[str]:
        """Enumerate objects visible via the global describe endpoint."""
        url = self._base_rest_url("/sobjects/")
        try:
            resp = self._get(url, as_guest=as_guest)
        except requests.RequestException as e:
            print(f"[!] Discovery request failed: {e}")
            return []

        if resp.status_code != 200:
            print(f"[i] Global describe not accessible ({resp.status_code}) as "
                  f"{'guest' if as_guest else 'unauthenticated'} caller — "
                  f"falling back to configured object list.")
            return []

        try:
            data = resp.json()
            names = [s["name"] for s in data.get("sobjects", [])]
            print(f"[+] Discovered {len(names)} objects via global describe "
                  f"({'guest' if as_guest else 'unauthenticated'} session).")
            return names
        except (ValueError, KeyError):
            return []

    def get_object_list(self) -> List[str]:
        objects: List[str] = []
        if self.cfg.get("auto_discover_objects", True):
            # Try as guest first (more likely to succeed / be the real attack
            # surface), then fully unauthenticated.
            if self.guest_session_id:
                objects = self.discover_objects(as_guest=True)
            if not objects:
                objects = self.discover_objects(as_guest=False)
        if not objects:
            objects = self.cfg.get("standard_objects", [])
        return objects

    # ---- probes ----

    def probe_sobject_describe(self, obj: str, as_guest: bool):
        caller = "guest_session" if as_guest else "unauthenticated"
        url = self._base_rest_url(f"/sobjects/{obj}/describe/")
        try:
            resp = self._get(url, as_guest=as_guest)
        except requests.RequestException as e:
            self.findings.append(Finding("sobject_describe", obj, caller, url, "GET",
                                          None, "ERROR", detail=str(e)))
            return

        if resp.status_code == 200:
            verdict = "FLAG"
            detail = "Object schema readable without proper authorization."
        elif resp.status_code in (401, 403, 404):
            verdict = "PASS"
            detail = f"Access denied/not found ({resp.status_code}) as expected."
        else:
            verdict = "PASS"
            detail = f"Unexpected status {resp.status_code}."

        self.findings.append(Finding("sobject_describe", obj, caller, url, "GET",
                                      resp.status_code, verdict, detail))

    def probe_sobject_query(self, obj: str, as_guest: bool):
        caller = "guest_session" if as_guest else "unauthenticated"
        fields = ",".join(self.probe_fields)
        soql = f"SELECT {fields} FROM {obj} LIMIT {self.row_limit}"
        url = self._base_rest_url("/query/") + f"?q={requests.utils.quote(soql)}"
        try:
            resp = self._get(url, as_guest=as_guest)
        except requests.RequestException as e:
            self.findings.append(Finding("sobject_query", obj, caller, url, "GET",
                                          None, "ERROR", detail=str(e)))
            return

        sample = None
        if resp.status_code == 200:
            verdict = "FLAG"
            detail = "Record data readable without proper authorization."
            try:
                body = resp.json()
                records = body.get("records", [])
                # Keep only a small, non-sensitive-looking preview: object
                # type + which fields came back, not the values themselves,
                # to avoid the report itself becoming a data leak.
                sample = {
                    "totalSize": body.get("totalSize"),
                    "fields_returned": sorted(
                        {k for r in records for k in r.keys() if k != "attributes"}
                    ),
                }
            except ValueError:
                pass
        elif resp.status_code in (401, 403):
            verdict = "PASS"
            detail = f"Access denied ({resp.status_code}) as expected."
        elif resp.status_code in (400, 404):
            verdict = "PASS"
            detail = f"Query rejected / object not queryable ({resp.status_code})."
        else:
            verdict = "PASS"
            detail = f"Unexpected status {resp.status_code}."

        self.findings.append(Finding("sobject_query", obj, caller, url, "GET",
                                      resp.status_code, verdict, detail, sample))

    def probe_apex_rest(self, path: str, as_guest: bool):
        caller = "guest_session" if as_guest else "unauthenticated"
        clean_path = path if path.startswith("/") else f"/{path}"
        url = f"{self.instance_url}/services/apexrest{clean_path}"
        try:
            resp = self._get(url, as_guest=as_guest)
        except requests.RequestException as e:
            self.findings.append(Finding("apex_rest", path, caller, url, "GET",
                                          None, "ERROR", detail=str(e)))
            return

        if resp.status_code == 200:
            verdict = "FLAG"
            detail = "Custom Apex REST endpoint returned data without proper authorization."
        elif resp.status_code in (401, 403, 404):
            verdict = "PASS"
            detail = f"Access denied/not found ({resp.status_code}) as expected."
        else:
            verdict = "PASS"
            detail = f"Unexpected status {resp.status_code} — review manually."

        self.findings.append(Finding("apex_rest", path, caller, url, "GET",
                                      resp.status_code, verdict, detail))

    # ---- orchestration ----

    def run(self):
        print(f"== Salesforce Guest/Unauthenticated API Audit ==")
        print(f"Target: {self.instance_url}  (API v{self.api_version})")
        print(f"Guest session provided: {'yes' if self.guest_session_id else 'no'}\n")

        objects = self.get_object_list()
        if not objects:
            print("[!] No objects to test (discovery failed and no static list configured).")
        else:
            print(f"[+] Testing {len(objects)} object(s)...\n")

        callers = [False]  # always test fully unauthenticated
        if self.guest_session_id:
            callers.append(True)  # also test as guest

        for obj in objects:
            for as_guest in callers:
                self.probe_sobject_describe(obj, as_guest)
                self.probe_sobject_query(obj, as_guest)

        for endpoint in self.cfg.get("custom_apex_endpoints", []):
            for as_guest in callers:
                self.probe_apex_rest(endpoint, as_guest)

        self.report()

    # ---- reporting ----

    def report(self):
        flags = [f for f in self.findings if f.verdict == "FLAG"]
        errors = [f for f in self.findings if f.verdict == "ERROR"]

        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total probes run : {len(self.findings)}")
        print(f"FLAGGED (exposed): {len(flags)}")
        print(f"Errors           : {len(errors)}\n")

        if flags:
            print("--- FLAGGED ENDPOINTS (review immediately) ---")
            for f in flags:
                print(f"  [{f.caller:14s}] {f.category:16s} {f.target:20s} "
                      f"-> HTTP {f.status_code}  ({f.detail})")
        else:
            print("No unauthenticated/guest read access was detected on the tested "
                  "endpoints. This does not guarantee the org is fully secure — "
                  "review Guest User sharing rules, FLS, and any Apex endpoints "
                  "not listed in 'custom_apex_endpoints' manually as well.")

        out_path = self.cfg.get("output_report_path", "sf_guest_audit_report.json")
        report_obj = {
            "instance_url": self.instance_url,
            "api_version": self.api_version,
            "total_probes": len(self.findings),
            "flagged_count": len(flags),
            "findings": [f.__dict__ for f in self.findings],
        }
        with open(out_path, "w") as fh:
            json.dump(report_obj, fh, indent=2)
        print(f"\n[+] Full report written to: {out_path}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r") as fh:
        return json.load(fh)


def main():
    parser = argparse.ArgumentParser(
        description="Audit a Salesforce org's standard/custom REST APIs for "
                    "unauthenticated or Guest User data exposure. Only use on "
                    "orgs you own or are authorized to test."
    )
    parser.add_argument("--config", default="config.json",
                        help="Path to config.json (default: config.json)")
    args = parser.parse_args()

    config = load_config(args.config)

    if "yourdomain" in config.get("instance_url", ""):
        print("[!] config.json still has the placeholder instance_url. "
              "Edit config.json to point at your org before running.")
        sys.exit(1)

    auditor = SalesforceGuestAuditor(config)
    auditor.run()


if __name__ == "__main__":
    main()
