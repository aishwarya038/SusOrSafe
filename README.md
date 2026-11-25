# AmIDataBroke

**SOC-lite Security Log Analysis Platform.**

A real, working AI-assisted security log triage tool. Paste a raw log or payload, and get an ML-based risk score, live threat intelligence, MITRE ATT&CK mapping, and actionable response playbooks. Nothing is mocked — every button calls a live backend endpoint.

## Features

1. **Live Threat Intelligence Lookup:** Backend calls the real AbuseIPDB API to return the actual abuse score, country, ISP, and report count for any IP.
2. **Raw Log Parser:** Uses real regex/JSON parsing to break down messy Apache/Nginx access logs, JSON blobs, or syslog text into clean fields (IP, timestamp, user, method, path, payload).
3. **PDF Forensic Report Generator:** Renders a real PDF on the fly from the log's actual stored data using ReportLab.
4. **CSV / JSON Bulk Export:** Streams your actual current database contents as a downloadable file.
5. **Compliance Audit Trail:** Every status change, single-log purge, and "Clear All" writes a real row to an `audit_logs` table, including the acting user and timestamp.
6. **Cross-Module Threat Correlation:** Groups stored logs by source IP, escalating priority when one address shows repeated attempts or multiple attack categories.
7. **MITRE ATT&CK Tagging:** Maps every detected category to a real MITRE ATT&CK technique ID (e.g., T1190).
8. **Auto-Refreshing Alert Queue:** The queue, KPIs, and audit trail poll the backend every 15s automatically.
9. **Real MTTA / MTTR Metrics:** Captures `investigating_at` / `resolved_at` timestamps the moment a human changes status, computing genuine Mean-Time-To-Acknowledge and Mean-Time-To-Resolve.
10. **Interactive Response Playbooks:** Ordered, per-category checklists of remediation steps. Checkbox progress is persisted per log in the database.
11. **Demo Seed Script:** Pushes realistic sample log lines through the real pipeline for a reliable, reproducible live demo.

## Tech Stack

**Frontend**
- Plain HTML + vanilla JavaScript (no framework)
- Tailwind CSS (via CDN)
- Chart.js for the threat-distribution donut chart

**Backend**
- Python 3 + FastAPI
- scikit-learn (TF-IDF vectorizer + Logistic Regression for ML scoring)
- ReportLab for PDF generation
- SQLite (Database)

## How to Run

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt

2. **Enable Threat Intelligence (Optional):**
   Copy `.env.example` to `.env` and paste your free [AbuseIPDB API key](https://www.abuseipdb.com/register). Without it, all features work except the Threat Intel panel.

3. **Start the backend:**
   ```bash
   uvicorn main:app --reload --port 8000

4. **Open the frontend:**
   Open `index.html` directly in your browser. Ensure `API_BASE` inside the `<script>` block matches your backend URL (default is `http://127.0.0.1:8000`).

5. **Populate demo data (Optional):**
   ```bash
   python seed_demo_data.py

6. **Use it:**
   - Sign up and sign in to access the dashboard (Overview, Analyze & Parse, Correlation, Log History, Audit Trail).
   - Paste a payload (e.g., `' OR 1=1 --`) or raw log line to see it analyzed and IP-checked live.
   - Check the Overview tab for real MTTA/MTTR metrics and the Audit Trail for real compliance logs.