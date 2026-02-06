# Snyk Application Compliance Reporter

A specialized auditing tool designed to report on the **Last Scanned Date** of applications within Snyk.

## Why this tool?

In Snyk, an "Application" typically corresponds to a **Target** (e.g., a GitHub Repo or Container Image), which is composed of multiple **Projects** (e.g., package.json, Dockerfile).

Standard Snyk reporting often hides "perfectly secure" apps because they have zero issues. This tool cross-references your absolute inventory with scan activity to ensure every application is accounted for, even those with zero vulnerabilities.

## Key Features

- **Gap Analysis**: Identifies "Ghost Repos" (Targets that exist but haven't been scanned or have no issues).
- **Smart Rollup**: Calculates the Application scan date based on the most recent scan of any nested project.
- **Compliance Tagging**: Automatically flags applications that exceed your defined monthly scan threshold.
- **Windsurf Ready**: Optimized for AI-assisted development and modular expansion.

## Getting Started

### Prerequisites

- Python 3.8+
- Snyk API Token (Service Account recommended for CI/CD)
- Snyk Organization ID

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/EmanAbelardF/snyk-compliance-reporter.git
   cd snyk-compliance-reporter
   ```

2. Set up Virtual Environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configure Environment:
   ```bash
   cp .env.example .env
   ```
   Add your `SNYK_TOKEN` and `SNYK_ORG_ID` to the `.env` file.

## Usage

Run the main script to generate a CSV report:
```bash
python main.py
```

### Understanding the Report (`compliance_status` column)

| Status | Description |
|--------|-------------|
| **COMPLIANT** | Scanned within the threshold (e.g., last 30 days). |
| **NON-COMPLIANT** | Target exists, but the last scan is older than the threshold. |
| **GHOST / ZERO-VULN** | **Critical Audit Note**: Target exists in inventory but has no vulnerability data. This repo is either 100% clean or hasn't been scanned since being imported. |

## Project Structure

- `main.py`: The execution entry point for Windsurf or CLI use.
- `.env.example`: Template for environment variables.
- `requirements.txt`: Python dependencies.

## Security

- **Tokens**: Never commit your `.env` file. It is included in `.gitignore` by default.
- **Scopes**: The API Token used requires **Org Admin** or **Group Admin** permissions to access the Export API.
