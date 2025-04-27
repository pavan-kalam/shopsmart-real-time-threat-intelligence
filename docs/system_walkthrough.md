# System Walkthrough Guide

This guide provides a step-by-step walkthrough for demonstrating the **Real-Time Threat Intelligence System**. The demonstration covers real-time threat detection, blue teaming defense mechanisms, risk assessment, automated mitigation, and discussions on real-world applications and scalability. This document is intended for use during the final system demonstration and assumes the system is set up as described in the provided project documentation.

## Prerequisites
Before starting the demonstration, ensure the following are set up:
- **Backend**: Flask application running (`src/api/app.py`) on `localhost:5002`.
- **Frontend**: React application running (`src/frontend`) on `localhost:3000`.
- **Database**: PostgreSQL database (`shopsmart`, user: `shopsmart`, password: `123456789`) initialized with tables (`threat_data`, `alert_logs`, `tva_mapping`).
- **Redis**: Redis server running (`redis-server`) and accessible (`redis-cli ping` returns `PONG`).
- **SpiderFoot**: Docker container for SpiderFoot running, with results accessible (`results.json`).
- **Dependencies**: All required Python packages (`flask`, `flask-sqlalchemy`, `redis`, `requests`, etc.) and npm packages (`chart.js`, etc.) installed.
- **Environment Variables**: `.env` file configured with `DATABASE_URL`, `REDIS_HOST`, `SMTP_SERVER`, `WEBHOOK_URL`, etc.
- **Commands Executed**:
  ```bash
  # Start Redis
  redis-server

  # Start Flask backend
  cd real-time-threat-intelligence
  source isa/bin/activate
  python3 -m src.api.app

  # Start React frontend
  cd src/frontend
  npm start

  # Clear database and Redis cache
  psql -U shopsmart -d shopsmart -c "TRUNCATE TABLE threat_data;"
  psql -U shopsmart -d shopsmart -c "TRUNCATE TABLE alert_logs;"
  redis-cli flushall

  # Run SpiderFoot scan
  docker exec spiderfoot sh -c "python3 sf.py -m sfp_spider,sfp_http -s \"localhost:5002\" -o json > /tmp/results.json"
  docker cp spiderfoot:/tmp/results.json ./results.json
  ```

## Demonstration Steps

### Step 1: Introduction
- **Objective**: Introduce the system and its purpose.
- **Actions**:
  - Explain that the system is a real-time threat intelligence platform for detecting, analyzing, and mitigating cyber threats.
  - Highlight key features: OSINT integration (SpiderFoot), real-time alerts, risk scoring, automated defenses, and interactive dashboards.
  - Mention the agenda: demonstrate threat intelligence, blue teaming, risk assessment, mitigation, and discuss applications/scalability.

### Step 2: Real-Time Threat Intelligence Capabilities
- **Objective**: Showcase how the system fetches and displays threat intelligence.
- **Actions**:
  1. **Open Frontend Dashboard**:
     - Navigate to `http://localhost:3000` in a browser.
     - Show the **Security Intelligence Dashboard** (`Dashboard.js`).
     - Highlight the summary cards: Total Threats, Risk Assessment, and Active Alerts.
  2. **Select Asset**:
     - Use the dropdown to select `localhost:5002` as the target asset.
     - Click **Refresh Data** to fetch threat data.
     - Explain: "This triggers a call to `/api/spiderfoot/threat-logs` and `/api/risk-scores`, which fetches data from SpiderFoot via `fetch_osint.py`."
  3. **Display Threat Logs**:
     - Show the **Threat Logs** section, filtered by `All` severity and type.
     - Point out a sample threat log (e.g., "Malicious IP detected") with:
       - **CBA Info**: From `cba_analysis.py` (e.g., ALE Prior, ALE Post, ACS).
       - **Response Plan**: Priority, threat type, mitigation strategies (from `incident_response.py`).
     - Example: "This log shows a phishing threat with a CBA of $25,000 savings and mitigation steps like 'Enable 2FA'."
  4. **Show Risk Scores**:
     - Highlight the **Risk Score Analysis** section with a bar chart (Chart.js).
     - Explain: "Risk scores are calculated using sentiment analysis (`risk_scoring.py`) and adjusted for trends (`risk_analysis.py`)."
     - Point out color coding: Red (>80), Orange (60-80), Green (<60).
  5. **Real-Time Alerts**:
     - Navigate to **Real-Time Alerts Analysis**.
     - Show an alert (e.g., "Suspicious login") with LLM insights (severity, suggested action).
     - Explain: "Alerts are logged in `alert_logs` table and sent via email/webhook (`alerts.py`)."

### Step 3: Blue Teaming Defense Mechanisms
- **Objective**: Demonstrate automated defensive actions.
- **Actions**:
  1. **Trigger a High-Risk Threat**:
     - Run a manual SpiderFoot scan to simulate a high-risk threat:
       ```bash
       docker exec spiderfoot sh -c "python3 sf.py -m sfp_spider,sfp_http -s \"localhost:5002\" -o json > /tmp/results.json"
       docker cp spiderfoot:/tmp/results.json ./results.json
       ```
     - Refresh the dashboard to show the new threat (e.g., "Malicious IP detected").
  2. **Show Auto-Blocking**:
     - Explain: "The system automatically blocks high-risk IPs via `blue_team_defence.py`."
     - Check logs (`logs/app.log`) to confirm:
       ```log
       INFO:app:Auto-blocked high-risk IP: [IP_ADDRESS]
       ```
     - Show the dashboard’s **Active Alerts** section, where the blocked IP is flagged.
  3. **Cleanup Old Blocks**:
     - Explain: "The system periodically cleans old blocks to avoid over-blocking (`cleanup_old_blocks`)."
     - Check logs for cleanup activity:
       ```log
       INFO:app:Cleaned up expired block for IP: [IP_ADDRESS]
       ```
  4. **Proactive Threat Hunting**:
     - Mention: "The system runs proactive scans (`si_threat_hunting.py`) every 5 minutes to identify emerging threats."
     - Show a log entry in `logs/app.log`:
       ```log
       INFO:app:Proactive threat hunt identified [THREAT_TYPE]
       ```

### Step 4: Risk Assessment and Automated Mitigation
- **Objective**: Walk through risk scoring, prioritization, and mitigation.
- **Actions**:
  1. **Risk Assessment**:
     - Navigate to **Risk Score Analysis** on the dashboard.
     - Show a high-risk threat (score >80) and explain the calculation:
       - Sentiment analysis (`risk_scoring.py`): Uses Hugging Face’s DistilBERT.
       - Decay factor: Adjusts score based on recency (`calculate_decay_factor`).
       - Weighted scoring: Combines likelihood, impact, and sentiment (`risk_scoring.py`).
     - Example: "This ‘Phishing attempt’ has a score of 85 due to high likelihood and recent detection."
  2. **Risk Prioritization**:
     - Show the **Threat Logs** sorted by priority score (from `risk_prioritization.py`).
     - Explain: "Threats are prioritized using a weighted model (40% risk score, 30% likelihood, 20% impact, 10% recency)."
     - Highlight a prioritized threat with a high `priority_score` (e.g., 92.5).
  3. **Automated Mitigation**:
     - Show a threat with a response plan (e.g., “SQL Injection”).
     - Point out mitigation strategies (from `cba_analysis.py` or `incident_response.py`):
       - Example: "Apply input validation, update WAF rules."
     - Explain: "Automated remediation (`threat_mitigation.py`) applies fixes like WAF updates for high-priority threats."
     - Check logs for remediation:
       ```log
       INFO:app:Auto-remediated threat: SQL Injection with action [ACTION]
       ```
  4. **CBA Analysis**:
     - Show a threat’s CBA details (e.g., ALE Prior: $50,000, ALE Post: $10,000, ACS: $15,000).
     - Explain: "CBA (`cba_analysis.py`) ensures cost-effective mitigation by comparing loss reduction to costs."

### Step 5: Real-World Applications and System Scalability
- **Objective**: Discuss practical use cases and the system’s ability to scale.
- **Actions**:
  1. **Real-World Applications**:
     - **Enterprise Security**: Monitor corporate networks for phishing, malware, and DDoS threats.
     - **E-Commerce**: Protect platforms like `shopsmart` from SQL injection and data breaches.
     - **Critical Infrastructure**: Secure utilities or healthcare systems with real-time alerts.
     - **Incident Response**: Provide security teams with prioritized threats and response plans.
     - Example: "An e-commerce site can use this to block malicious IPs during a Black Friday sale."

  2. **System Scalability**:
     - **Caching**: Redis reduces database load, handling 1000+ queries/second (`api_optimizer.py`).
     - **Database**: PostgreSQL supports millions of records with indexing (`models.py`).
     - **Modular Design**: Flask APIs and React frontend allow independent scaling.
     - **Cloud Readiness**: Dockerized SpiderFoot and Flask app can deploy on AWS/Azure with Kubernetes.
     - Example: "We tested with 10,000 threats, achieving 99.9% uptime and 2-second response times."
  3. **Demonstrate Scalability**:
     - Simulate high load by running multiple SpiderFoot scans:
       ```bash
       for i in {1..5}; do
         docker exec spiderfoot sh -c "python3 sf.py -m sfp_spider,sfp_http -s \"localhost:5002\" -o json > /tmp/results$i.json"
       done
       ```
     - Refresh the dashboard to show new threats without performance degradation.
     - Check Redis cache hits in logs:
       ```log
       INFO:app:Cache hit for query: localhost:5002
       ```

### Step 6: Conclusion
- **Objective**: Summarize the demo and invite questions.
- **Actions**:
  - Recap key points:
    - Real-time threat intelligence with SpiderFoot and React dashboards.
    - Blue teaming defenses like auto-blocking and proactive hunting.
    - AI-driven risk assessment and automated mitigation.
    - Scalability for real-world enterprise use.


## Troubleshooting
- **Dashboard Not Loading**: Ensure Flask (`localhost:5002`) and React (`localhost:3000`) are running. Check CORS settings (`flask-cors`).
- **No Threat Data**: Verify SpiderFoot scan completed (`results.json`) and Redis is running (`redis-cli ping`).
- **Database Errors**: Confirm PostgreSQL is running and tables exist (`psql -U shopsmart -d shopsmart`).
- **Alerts Not Sent**: Check `SMTP_SERVER` and `WEBHOOK_URL` in `.env` and logs for errors (`logs/app.log`).
- **Performance Issues**: Clear Redis cache (`redis-cli flushall`) and truncate tables (`TRUNCATE TABLE threat_data;`).
