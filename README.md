# Salesforce WebRuntime GraphQL Auditor

A lightweight Python utility and standalone executable for auditing Salesforce WebRuntime GraphQL endpoints. It tests SObject access, retrieves total record counts, and generates both console output and an HTML report.

---

## Features

- **Automated SObject Auditing**: Queries target SObject record counts via Salesforce WebRuntime GraphQL UI API.
- **Standalone Windows Executable**: Runs without requiring Python or pip dependencies to be installed on target machines.
- **HTML Reports**: Automatically generates a self-contained, dark-mode HTML report for audit results.
- **External Configuration**: Uses an external `ec-config.json` file for flexible configuration without recompiling.

---

## Configuration (`ec-config.json`)

The application expects an `ec-config.json` file in the same directory as the executable (or Python script).

Create or edit `ec-config.json` with the following structure:

```json
{
  "site_url": "[https://orgfarm-example.develop.my.site.com/aflabs](https://orgfarm-example.develop.my.site.com/aflabs)",
  "api_version": "v66.0",
  "output_html": "audit_report.html",
  "objects": [
    "Account",
    "Contact",
    "User",
    "Lead",
    "Opportunity"
  ]
}

```
| Parameter | Type | Description |
|-----------|------|-------------|
| `site_url` | String | The base URL of the target Salesforce WebRuntime site. |
| `api_version` | String | Salesforce API version (default: `v66.0`). |
| `output_html` | String | Filename/path for the output HTML report. |
| `objects` | Array | List of SObject API names to query. |

## Running on Windows

### Method 1: Running the Standalone Executable (`.exe`)

No Python installation is required for this method.

1. Download or extract `sf_audit_graphql.exe`.
2. Place `ec-config.json` in the same directory as `sf_audit_graphql.exe`:

```text
sf_audit/
├── ec-config.json
└── sf_audit_graphql.exe

DOS
sf_audit_graphql.exe
```

3. Open the generated HTML report (e.g., `audit_report.html`) in any web browser.