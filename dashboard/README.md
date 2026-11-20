# 🛡️ Shadow AI & DLP Governance Dashboard

The **Shadow AI & DLP Governance Dashboard** provides real-time visibility, threat analytics, and policy enforcement metrics for corporate AI traffic. It monitors employee prompts sent to LLMs, identifies sensitive data leaks (PII, credentials, cloud keys), blocks unauthorized consumer AI domains, and displays deep inspection logs.

---

## 🚀 How to Run

### Option 1: Docker Compose (Full Stack - Recommended)
The dashboard is integrated into the multi-container hackathon stack in `compose.yaml`:

```bash
docker compose up --build
```

Services exposed:
- **DLP Governance Dashboard**: [http://localhost:8502](http://localhost:8502)
- **Employee Workstation**: [http://localhost:8501](http://localhost:8501)
- **AI Gateway & DLP Judge**: [http://localhost:8000](http://localhost:8000) (Docs at `/docs`, Logs at `/logs`)

---

### Option 2: Streamlit (Python Standalone)
If running outside Docker with Python 3.11+:

```bash
cd dashboard
pip install -r requirements.txt
streamlit run app.py --server.port 8502
```

The app connects to PostgreSQL if available, falls back to the Judge HTTP API (`http://localhost:8000/logs`), or runs in **Demo Mode** with realistic sample data and a live prompt tester.

---

### Option 3: Node.js (Zero External Dependencies)
If running locally with Node.js:

```bash
cd dashboard
node server.js
```

Open [http://localhost:8502](http://localhost:8502) in your browser.

---

### Option 4: Direct Browser View
You can directly open `dashboard/index.html` in any browser (Chrome, Edge, Firefox) without running any server.

---

## ✨ Key Features

1. **Executive KPI Metrics**:
   - Total Monitored Prompts
   - Critical Blocked Requests (HTTP 403)
   - PII Redacted & Sanitized Prompts
   - Compliant & Allowed Requests
   - Flagged Employee Accounts

2. **Visual Threat Analytics**:
   - Action Distribution (Donut & Bar charts: BLOCK vs REDACT vs ALLOW)
   - Top Detected Vulnerabilities (AWS Keys, Emails, SSNs, DB URLs, Private Keys)
   - User Risk Leaderboard (Offenders by frequency)
   - Threat Activity Timeline

3. **Incident Explorer & Deep Inspector**:
   - Live stream with action badges (🔴 BLOCK, 🟡 REDACT, 🟢 ALLOW)
   - Search by user, prompt keyword, IP, or finding
   - Side-by-side prompt comparison:
     - **Original Employee Input** vs **Sanitized/Forwarded Prompt**

4. **Interactive DLP Scanner**:
   - Test any prompt in real time against regex signatures.
   - Presets for AWS Keys, SSN/Email PII, DB URLs, and clean code.
   - Option to log tested prompts into the database.

5. **Clean Zero-State Logging**:
   - Starts completely clean with 0 dummy records.
   - Logs only real prompts submitted by you from the Employee Workstation.
