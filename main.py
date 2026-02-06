import os
import time
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load credentials from .env file
load_dotenv()

SNYK_TOKEN = os.getenv('SNYK_TOKEN')
ORG_ID = os.getenv('SNYK_ORG_ID')
THRESHOLD = int(os.getenv('COMPLIANCE_THRESHOLD_DAYS', 30))

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

HEADERS = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json"
}


def request_with_retry(method, url, **kwargs):
    """Make HTTP request with retry logic for rate limiting (429) and transient errors."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.request(method, url, **kwargs)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', RETRY_DELAY * (2 ** attempt)))
                print(f"    [!] Rate limited. Retrying after {retry_after}s (attempt {attempt + 1}/{MAX_RETRIES})...")
                time.sleep(retry_after)
                continue
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2 ** attempt)
                print(f"    [!] Request failed: {e}. Retrying in {wait_time}s (attempt {attempt + 1}/{MAX_RETRIES})...")
                time.sleep(wait_time)
            else:
                raise
    
    raise Exception(f"Max retries ({MAX_RETRIES}) exceeded for {url}")

def fetch_inventory():
    """Retrieves all Targets from the Snyk REST API (Inventory Source of Truth)"""
    print(f"[*] Fetching inventory for Org: {ORG_ID}...")
    targets = []
    url = f"https://api.snyk.io/rest/orgs/{ORG_ID}/targets?version=2024-10-15"
    
    while url:
        response = request_with_retry('GET', url, headers=HEADERS)
        data = response.json()
        targets.extend([{"target_name": t['attributes']['display_name']} for t in data.get('data', [])])
        
        # Safe pagination: check if 'next' exists and is not None/empty
        links = data.get('links', {})
        next_link = links.get('next') if links else None
        url = next_link if next_link else None
    
    print(f"    [+] Found {len(targets)} targets")
    return pd.DataFrame(targets)

def fetch_scan_data():
    """Triggers and polls the Snyk Export API for latest scan timestamps"""
    print("[*] Requesting scan data from Export API...")
    post_url = f"https://api.snyk.io/rest/orgs/{ORG_ID}/exports"
    payload = {
        "data": {
            "attributes": {
                "type": "issues",
                "format": "json",
                "columns": ["target_name", "last_tested_date"]
            }
        }
    }
    
    trigger_resp = request_with_retry('POST', post_url, json=payload, headers=HEADERS)
    export_id = trigger_resp.json()['data']['id']

    # Polling Logic with failure detection
    status = "queued"
    max_poll_attempts = 60  # Max 15 minutes of polling (60 * 15s)
    poll_count = 0
    
    while status not in ("completed", "failed"):
        print(f"    - Current status: {status}. Waiting 15s...")
        time.sleep(15)
        poll_count += 1
        
        if poll_count >= max_poll_attempts:
            raise Exception(f"Export polling timed out after {max_poll_attempts * 15 / 60} minutes")
        
        poll_resp = request_with_retry('GET', f"{post_url}/{export_id}", headers=HEADERS).json()
        status = poll_resp['data']['attributes']['status']
    
    # Check for export failure
    if status == "failed":
        error_msg = poll_resp['data']['attributes'].get('error', 'Unknown error')
        raise Exception(f"Snyk Export API job failed: {error_msg}")

    print("[*] Download complete. Processing results...")
    download_url = poll_resp['data']['attributes']['url']
    return pd.read_json(download_url)

def run_report():
    try:
        # 1. Get absolute list of all repos
        inventory = fetch_inventory()

        # 2. Get scan dates for apps with vulnerabilities
        scans = fetch_scan_data()
        scans['last_tested_date'] = pd.to_datetime(scans['last_tested_date'])
        
        # Aggregate to find the newest scan per application
        latest_scans = scans.groupby('target_name')['last_tested_date'].max().reset_index()

        # 3. Join Inventory and Scans (identifies 'Ghost' repos)
        report = pd.merge(inventory, latest_scans, on='target_name', how='left')

        # 4. Compliance Logic
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=THRESHOLD)

        def evaluate(row):
            if pd.isna(row['last_tested_date']):
                return "GHOST / ZERO-VULN"
            return "COMPLIANT" if row['last_tested_date'] >= cutoff else "NON-COMPLIANT"

        report['compliance_status'] = report.apply(evaluate, axis=1)
        
        # Save results
        filename = f"snyk_report_{datetime.now().strftime('%Y%m%d')}.csv"
        report.to_csv(filename, index=False)
        print(f"\n[SUCCESS] Report generated: {filename}")
        print(report['compliance_status'].value_counts())

    except Exception as e:
        print(f"\n[ERROR] {e}")

if __name__ == "__main__":
    run_report()
