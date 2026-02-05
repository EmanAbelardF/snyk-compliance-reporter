# Snyk Application Compliance Reporter

This tool identifies "Ghost Repositories" and stale scans across your Snyk Organization by cross-referencing the **REST API** (Inventory) with the **Export API** (Issue Data).

## How it works
Snyk's Export API only returns data for projects with active vulnerabilities. This script fills the "Zero-Vuln Gap" by:
1. Fetching every Target registered in Snyk.
2. Fetching the latest scan dates for all Issues.
3. Flagging apps that haven't been scanned within your defined window (default: 30 days).

## Setup
1. Clone the repo: `git clone <your-url>` 
2. Install dependencies: `pip install -r requirements.txt` 
3. Copy `.env.example` to `.env` and add your `SNYK_TOKEN` and `SNYK_ORG_ID`.
4. Run: `python main.py` 

## Compliance Statuses
- **COMPLIANT**: Scanned within the threshold.
- **NON-COMPLIANT**: Scanned over 30 days ago.
- **GHOST / ZERO-VULN**: Target exists in Snyk but has no issue data (indicates a perfectly clean repo or a failed initial scan).

## Troubleshooting Common Issues

- **401 Unauthorized**: Your API token is incorrect or has expired.

- **403 Forbidden**: You do not have "Group Admin" or "Org Admin" permissions. The Export API requires high-level permissions.

- **429 Rate Limit Exceeded**: You are making too many requests. Wait a few minutes and try again.

- **Empty Results**: If the script returns an empty list, ensure that your Organization actually has Targets imported and that at least one scan has been completed.

- **Long Polling Times**: For Organizations with thousands of projects, the "Polling" phase may take several minutes. This is normal as Snyk is generating a large dataset on the backend.
