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

HEADERS = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json"
}

def fetch_inventory():
    """Retrieves all Targets from the Snyk REST API (Inventory Source of Truth)"""
    print(f"[*] Fetching inventory for Org: {ORG_ID}...")
    targets = []
    url = f"https://api.snyk.io/rest/orgs/{ORG_ID}/targets?version=2024-10-15"
    
    while url:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()
        targets.extend([{"target_name": t['attributes']['display_name']} for t in data['data']])
        url = data.get('links', {}).get('next')
    
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
    
    trigger_resp = requests.post(post_url, json=payload, headers=HEADERS)
    trigger_resp.raise_for_status()
    export_id = trigger_resp.json()['data']['id']

    # Polling Logic
    status = "queued"
    while status != "completed":
        print(f"    - Current status: {status}. Waiting 15s...")
        time.sleep(15)
        poll_resp = requests.get(f"{post_url}/{export_id}", headers=HEADERS).json()
        status = poll_resp['data']['attributes']['status']

    print("[*] Download complete. Processing results...")
    return pd.read_json(poll_resp['data']['attributes']['url'])

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
