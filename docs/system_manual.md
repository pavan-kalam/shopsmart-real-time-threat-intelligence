# System Manual
## ThreatSync: Automated Threat Intelligence System

This document provides a comprehensive guide for installing, configuring, and using the ThreatSync system, a Flask-based threat intelligence platform with automated mitigation capabilities.

---

## 1. System Overview

ThreatSync is a cybersecurity platform designed to collect, analyze, and mitigate threats using OSINT (via SpiderFoot), AI-driven anomaly detection, and automated blue teaming defenses. It includes a Flask backend, PostgreSQL database, React frontend, and background processes for real-time threat monitoring.

Key features:
- Real-time threat data collection and risk scoring.
- AI-powered anomaly detection using Hugging Face models.
- Automated IP blocking, sandboxing, and remediation.
- Web-based dashboard for threat visualization.
- Periodic report generation and database backups.

---

## 2. Installation & Setup

### 2.1 Prerequisites

- **Operating System**: macOS.
- **Software**:
  - Python 3.8+
  - PostgreSQL 15
  - Node.js 16+ (for frontend)
  - `iptables` (for IP blocking)
  - `pg_dump` (for database backups)
  - SpiderFoot 4.0+ (for OSINT collection)
- **Hardware**: 4GB RAM, 2-core CPU, 20GB disk space.
- **Python Packages**:
  - Flask, Flask-SQLAlchemy, Flask-Migrate, Flask-CORS
  - transformers (Hugging Face)
  - werkzeug
  - sqlalchemy, psycopg2-binary
- **Node Packages**:
  - React, axios, recharts

### 2.2 Installation Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/pavan-kalam/shopsmart-real-time-threat-intelligence.git

2. **Install PostgreSQL**:
   - Download and install PostgreSQL from the official website and 'pgAdmin4'.
   - Create a database named 'shopsmart' and a user with and owner with the same name with password '123456789'.

3. **Install Spiderfoot**
   - Download and install docker, and open terminal in the docker and redirect to project directory, and run the below commands.
   - The below commands will clone the spiderfoot software from the git repository, built the image and run the container.

   ```bash
   git clone https://github.com/smicallef/spiderfoot.git
   cd spiderfoot
   docker build -t spiderfoot/spiderfoot .  
   ls -la
   docker run -d -p 5001:5001 --name spiderfoot spiderfoot/spiderfoot

4. **Install Frontend dependencies**
   ```bash
   cd real-time-threat-intelligence/src/frontend
   npm install
   npm install chart.js

5. **Install python dependencies**
   ```bash
   source isa/bin/activate
   pip install flask flask-migrate flask-cors transformers werkzeug
   pip install redis requests sqlalchemy psycopg2-binary flask-sqlalchemy


### 2.3 Starting the system

1. **Initial database**
   - Make sure pgAdmin4 is active in the background
   - Open terminal in the project directory and run the below command to create and initialise the database.
   ```bash
   source isa/bin/activate
   pip install flask-migrate
   flask --app src.api.app db init
   flask run
   flask --app src.api.app db migrate -m "Initial migration"
   flask --app src.api.app db upgrade
   ```

2. **Install and start the redis server**
   - Open terminal in the project root directory and run the below command to install and start the redish server.
   ```bash
   brew install redis
   redis-server
   ```
   - Open another terminal to clear the redis cashe
   ```bash
   redis-cli flushall
   ```

3. **Start the Spiderfoot**
   - Open the docker and just run the Spiderfoot container which is already created in the previous.
   - Open the browser and navigate to 'http://localhost:5001' to access the Spiderfoot web interface.

4. **Start the Backend**
   - Open the new terminal in the project root directory and run the below commands to start the backend.
   ```bash
   source isa/bin/activate
   cd real-time-threat-intelligence
   python -m src.api.app
   ```
5. **Start the Frontend**
   - Open the new terminal in the project directory and run the below command,
   ```bash
   cd src/frontend
   npm start
   ```
6. **(Optional: Truncate the threat database)**
   - If you want to start a fresh database, you can truncate the threat database by running the below command.
   ```bash
   psql -U shopsmart -d shopsmart
   Password:123456789
   TRUNCATE TABLE alert_logs;
   TRUNCATE TABLE threat_data;

### 2.4 Verifying Installation
- Access the dashboard at http://localhost:3000.
- Log in with a test user (register via /api/register).
- Check logs in logs/app.log for backend activity.
- Verify database tables (users, threat_data, alert_logs, etc.) in PostgreSQL.


## 3. Using the threat intelligence dashboard
- The dashboard, built with React, provides a user-friendly interface for monitoring and managing threats.

### 3.1 Accessing the dashboard
- URL: http://localhost:3000
- Login:
    - Register a new user via the "Sign Up" page.
    - Log in with your credentials.

### 3.2 Dashboard features
- Threat Logs:
    - Displays real-time threat data from SpiderFoot.
    - Columns: Description, Threat Type, Risk Score, Created At, Mitigation.
    - Filter by risk score or threat type.
- Assets:
    - Lists monitored assets (e.g., IPs, domains).
    - Add new assets via the API (/api/assets).
- Alerts:
    - We will get an email shows high-risk alerts (risk score ≥75).
    - Details include threat description and suggested actions.
- Reports:
    - Download periodic PDF reports from the "Reports" tab.
    - Generated hourly and stored in reports/.

## 4. Automated Mitigation Mechanisms
- The system includes automated mitigation mechanisms for high-risk scores

### 4.1 IP Blocking (blue_team_defence.py)
- Functionality:
    - Scans threat_data for high-risk IPs (risk score ≥80, last 24 hours).
    - Blocks IPs using iptables (INPUT chain, DROP action).
    - Logs actions to logs/blocked_ips.log and alert_log table.
- Cleanup:
    - Unblocks IPs after 24 hours.
    - Removes expired alert_log entries.
- Configuration:
    - Block duration: 24 hours (modify BLOCK_DURATION in blue_team_defence.py).
    - Requires iptables installed and executable at /sbin/iptables.

### 4.2 AI-Powered Threat Hunting (ai_threat_hunting.py)
- Functionality:
    - Analyzes threats from the last 48 hours using Hugging Face’s zero-shot classifier (facebook/bart-large-mnli).
    - Labels threats as "Normal," "Suspicious," or "Malicious."
    - Logs Suspicious/Malicious threats (confidence >0.7) to alert_log with adjusted risk scores.
- Proactive Hunting:
    - Fetches fresh OSINT data via SpiderFoot.
    - Processes and analyzes new threats for anomalies.
- Configuration:
    - Modify query in proactive_threat_hunt (default: localhost:5002).

### 4.3 Threat Remediation (threat_mitigation.py)
- Functionality:
    - Targets high-risk threats (score ≥75, last 24 hours).
    - Isolates threats in a sandbox directory (sandbox/).
    - Applies mitigation strategies from cba_analysis.py (e.g., patch, isolate).
    - Logs actions to alert_log.
- Sandboxing:
    - Creates isolated directories for artifacts (extendable to tools like Cuckoo Sandbox).
    - Timeout: 300 seconds (modify SANDBOX_TIMEOUT).
- Configuration:
    - Sandbox path: sandbox/ (ensure write permissions).

### 4.4 Background Execution
- All mitigation tasks run every 5 minutes via a background thread in app.py (start_defensive_mechanisms).
- Logs are stored in logs/ for auditing.

## 5. Maintenance
- **Logs:** Check logs/app.log, logs/blocked_ips.log for issues.
- **Backups:** Database backups are stored in backups/ (hourly).
- **Updates:**
    - Update Python packages
    - Update Node packages: npm update in src/frontend.

## 6. Troobleshooting
- Database Connection Error:
    - Verify PostgreSQL is running: sudo systemctl status postgresql.
    - Check credentials in .env.
- Frontend Not Loading:
    - Ensure npm start is running in src/frontend.
    - Check CORS settings in app.py.
- IP Blocking Fails:
    - Verify iptables permissions: sudo chmod +x /sbin/iptables.
- AI Model Issues:
    - Ensure transformers is installed and internet access for model download.