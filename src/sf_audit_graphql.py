from datetime import datetime
import json
import os
import sys
import urllib.parse
import requests


def get_external_path(filename):
    """
    Locates external files (like ec-config.json) outside the compiled PyInstaller executable:
    1. Checks current working directory (CWD).
    2. Checks the directory where the binary/script resides.
    """
    cwd_path = os.path.join(os.getcwd(), filename)
    if os.path.exists(cwd_path):
        return cwd_path

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    exe_path = os.path.join(exe_dir, filename)
    if os.path.exists(exe_path):
        return exe_path

    return cwd_path


def load_config(config_filename="ec-config.json"):
    """Loads target URL, object list, and output configuration."""
    config_path = get_external_path(config_filename)
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"Configuration file '{config_filename}' not found at: {config_path}"
        )

    print(f"[+] Loading configuration from: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_endpoint(site_url, api_version="v66.0"):
    """Constructs the Salesforce WebRuntime GraphQL endpoint."""
    parsed = urllib.parse.urlparse(site_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    return f"{base_url}{path}/webruntime/api/services/data/{api_version}/graphql"


def get_record_count(endpoint, headers, object_name):
    """Queries totalCount for a specific SObject independently."""
    query = f"""
    query {{
      uiapi {{
        query {{
          {object_name}(first: 1) {{
            totalCount
          }}
        }}
      }}
    }}
    """

    try:
        response = requests.post(
            endpoint, headers=headers, json={"query": query}, timeout=10
        )

        if response.status_code != 200:
            return {"status": f"HTTP {response.status_code}", "count": None}

        data = response.json()

        # Handle GraphQL errors safely
        if "errors" in data and data["errors"]:
            err = data["errors"][0]
            err_msg = (
                err.get("message", str(err)) if isinstance(err, dict) else str(err)
            )
            if "FieldUndefined" in err_msg:
                return {"status": "Disabled / Undefined in Schema", "count": 0}
            return {"status": f"Error: {err_msg}", "count": None}

        # Parse valid count
        if "data" in data and data["data"] and data["data"].get("uiapi"):
            query_res = data["data"]["uiapi"].get("query", {})
            obj_res = query_res.get(object_name) if query_res else None

            if obj_res is not None:
                count = obj_res.get("totalCount", 0)
                return {"status": "Accessible", "count": count}

        return {"status": "Restricted / Null Response", "count": 0}

    except Exception as e:
        return {"status": f"Execution Error: {str(e)}", "count": None}


def generate_html_report(site_url, endpoint, results, output_filename):
    """Generates a styled, standalone HTML audit report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_objects = len(results)
    accessible_count = sum(
        1 for r in results if r["result"]["status"] == "Accessible"
    )
    disabled_count = sum(
        1
    for r in results
    if r["result"]["status"] == "Disabled / Undefined in Schema"
    )
    errors_count = total_objects - (accessible_count + disabled_count)

    table_rows = ""
    for r in results:
        obj = r["object"]
        status = r["result"]["status"]
        count = (
            f"{r['result']['count']:,}"
            if r["result"]["count"] is not None
            else "N/A"
        )

        # Map status to CSS classes
        if status == "Accessible":
            badge_class = "badge-success"
        elif "Disabled" in status:
            badge_class = "badge-secondary"
        else:
            badge_class = "badge-danger"

        table_rows += f"""
        <tr>
            <td class="obj-name">{obj}</td>
            <td class="count-val">{count}</td>
            <td><span class="badge {badge_class}">{status}</span></td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Salesforce GraphQL Security Audit</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --accent: #38bdf8;
            --success: #22c55e;
            --warning: #eab308;
            --danger: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }}
        .header h1 {{
            margin: 0 0 0.5rem 0;
            font-size: 1.875rem;
            color: var(--accent);
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem 1.25rem;
        }}
        .card .label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}
        .card .value {{
            font-size: 1.25rem;
            font-weight: 600;
            word-break: break-all;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .stat-card .num {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .stat-card.accessible .num {{ color: var(--success); }}
        .stat-card.disabled .num {{ color: var(--text-muted); }}
        .stat-card.errors .num {{ color: var(--danger); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 0.875rem 1.25rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #111827;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .obj-name {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-weight: 600;
        }}
        .count-val {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.625rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 9999px;
            text-transform: uppercase;
        }}
        .badge-success {{ background: rgba(34, 197, 94, 0.15); color: var(--success); border: 1px solid var(--success); }}
        .badge-secondary {{ background: rgba(148, 163, 184, 0.15); color: var(--text-muted); border: 1px solid var(--text-muted); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid var(--danger); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Salesforce GraphQL Audit Report</h1>
            <div style="color: var(--text-muted); font-size: 0.875rem;">Generated on {timestamp}</div>
        </div>

        <div class="meta-grid">
            <div class="card">
                <div class="label">Target Site</div>
                <div class="value" style="font-size: 0.95rem;">{site_url}</div>
            </div>
            <div class="card">
                <div class="label">Endpoint</div>
                <div class="value" style="font-size: 0.8rem; color: var(--text-muted);">{endpoint}</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Queried</div>
                <div class="num">{total_objects}</div>
            </div>
            <div class="stat-card accessible">
                <div class="label">Accessible</div>
                <div class="num">{accessible_count}</div>
            </div>
            <div class="stat-card disabled">
                <div class="label">Disabled</div>
                <div class="num">{disabled_count}</div>
            </div>
            <div class="stat-card errors">
                <div class="label">Errors / Restricted</div>
                <div class="num">{errors_count}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>SObject Name</th>
                    <th>Record Count</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    # Resolve output location
    out_path = os.path.abspath(output_filename)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] HTML report successfully generated at: {out_path}")


def run_audit():
    try:
        config = load_config("ec-config.json")
    except FileNotFoundError as e:
        print(f"[-] Configuration Error:\n{e}")
        sys.exit(1)

    site_url = config.get("site_url")
    api_version = config.get("api_version", "v66.0")
    objects = config.get("objects", [])
    output_html = config.get("output_html", "audit_report.html")

    endpoint = build_endpoint(site_url, api_version)
    headers = {
        "Content-Type": "application/json",
        "Cookie": "CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1",
    }

    print(f"\n[+] TARGET: {site_url}")
    print(f"[+] ENDPOINT: {endpoint}")
    print("=" * 65)
    print(f"{'OBJECT TYPE':<20} | {'RECORD COUNT':<15} | {'STATUS'}")
    print("-" * 65)

    results = []

    for obj in objects:
        res = get_record_count(endpoint, headers, obj)
        results.append({"object": obj, "result": res})

        count_display = str(res["count"]) if res["count"] is not None else "N/A"
        print(f"{obj:<20} | {count_display:<15} | {res['status']}")

    print("=" * 65 + "\n")

    # Generate external HTML file configured in config
    generate_html_report(site_url, endpoint, results, output_html)


if __name__ == "__main__":
    run_audit()