import json
import urllib.parse
import requests


def load_config(config_path="ec-config.json"):
    """Loads target URL and object list from local config."""
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
            err_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
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


def run_audit():
    config = load_config()
    site_url = config.get("site_url")
    api_version = config.get("api_version", "v66.0")
    objects = config.get("objects", [])

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

    for obj in objects:
        res = get_record_count(endpoint, headers, obj)
        count_display = str(res["count"]) if res["count"] is not None else "N/A"
        print(f"{obj:<20} | {count_display:<15} | {res['status']}")

    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_audit()