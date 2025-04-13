
**Explanation**:
- **Installation**: Detailed steps for setting up Python, PostgreSQL, SpiderFoot, and frontend dependencies, including specific commands and configurations from the project.
- **Mitigation**: Explains the new features (`blue_team_defence`, `ai_threat_hunting`, `threat_mitigation`,`incident_response`, `risk_analysis`, `mitigation_recommendations`,`risk_scoring`,`risk_prioritization`,`alerts`,`api_optimizer`) in technical detail, including configuration options and logs.
- **Maintenance/Troubleshooting**: Provides practical tips aligned with the project’s setup (e.g., database URI, log paths).

---

#### Deliverable 2: User Guide for Analysts (`/docs/user_guide.md`)

This is for blue team analysts, focusing on usability and clarity without requiring deep technical knowledge.

```markdown
# User Guide for Blue Team Analysts
## real-time-threat-intelligence: Your Threat Intelligence Dashboard

Welcome to real-time-threat-intelligence, a powerful tool to help blue team analysts monitor, analyze, and respond to cyber threats in real time. This guide explains how to use the system effectively, focusing on the dashboard and automated defenses.

---

## 1. Getting Started

### 1.1 real-time-threat-intelligence

real-time-threat-intelligence is a cybersecurity platform that:
- Collects threat data from open sources (e.g., SpiderFoot).
- Scores threats based on risk (1-100).
- Alerts you to high-risk threats (score ≥75).
- Automatically blocks malicious IPs, detects anomalies, and isolates threats.
- Provides a web dashboard to view and manage threats.

### 1.2 Accessing the Dashboard

1. **Open the Dashboard**:
   - URL: `http://localhost:3000`.
   - Use a web browser like Chrome or Firefox.

2. **Log In**:
   - **New User**:
     - Click "Sign Up."
     - Enter a username and password.
     - Click "Register."
   - **Existing User**:
     - Enter your username and password.
     - Click "Log In."

3. **Dashboard Overview**:
   - **Threat Logs**: Shows recent threats (e.g., malicious IPs, domains).
   - **Assets**: Lists systems you’re protecting (e.g., servers).
   - **Alerts**: Highlights urgent threats.
   - **Reports**: Downloadable summaries of threat activity.

---

## 2. Using the Dashboard

### 2.1 Viewing Threats

- **Tab**: "Threat Logs"
- **What You’ll See**:
  - **Description**: Details of the threat (e.g., "Malicious IP 192.168.1.1 detected").
  - **Threat Type**: Category (e.g., IP, Malware, Phishing).
  - **Risk Score**: 1-100 (higher is worse; ≥75 triggers alerts).
  - **Created At**: When the threat was detected.
  - **Mitigation**: Suggested actions (e.g., "Block IP", "Patch system").
- **Actions**:
  - **Filter**: Sort by risk score or type (e.g., show only "IP" threats).
  - **Search**: Find threats by keyword (e.g., "192.168").
  - **Details**: Click a threat to see more info, including cost-benefit analysis (CBA).

### 2.2 Managing Alerts

- **Tab**: "Alerts"
- **Purpose**: Shows high-risk threats needing immediate attention.
- **Details**:
  - Threat description and type.
  - Risk score and timestamp.
  - Suggested response (e.g., "Investigate immediately").
- **Actions**:
  - **Acknowledge**: Mark an alert as handled to clear it.
  - **Escalate**: Notify your team via email (configure in "Settings").
  - **View History**: See past alerts in the "Alert Log."

### 2.3 Monitoring Assets

- **Tab**: "Assets"
- **Purpose**: Tracks systems you’re protecting (e.g., servers, domains).
- **Details**:
  - Name, type (e.g., IP, domain), and identifier.
- **Actions**:
  - **Add Asset**: Contact your admin to add new systems via the API.
  - **Check Status**: See if threats are linked to an asset.

### 2.4 Downloading Reports

- **Tab**: "Reports"
- **Purpose**: Summarizes threat activity for sharing or review.
- **How to Use**:
  - Click "Download Latest Report" to get a PDF.
  - Reports are generated hourly and include:
    - Top threats by risk score.
    - Mitigation actions taken.
    - Trends (e.g., increasing IP-based attacks).
  - Save or share reports with your team.

---

## 3. Understanding Automated Defenses

- real-time-threat-intelligence automates several defensive actions to reduce your workload. Here’s what happens behind the scenes:

### 3.1 Blocking Malicious IPs

- **What It Does**:
  - Finds IPs with high risk (score ≥80) from the last 24 hours.
  - Blocks them using firewall rules to stop attacks.
  - Unblocks IPs after 24 hours if safe.
- **Your Role**:
  - Check "Alerts" for blocked IPs (labeled "IP Blocked").
  - Review logs if an IP was blocked in error (contact admin to unblock manually).

### 3.2 Detecting Anomalies with AI

- **What It Does**:
  - Uses AI to analyze threats (last 48 hours).
  - Flags "Suspicious" or "Malicious" behaviors (e.g., unusual traffic patterns).
  - Alerts you if the AI is confident (score >0.7).
- **Your Role**:
  - Look for "AI-Detected Suspicious" or "AI-Detected Malicious" alerts.
  - Investigate flagged threats to confirm if they’re real.

### 3.3 Isolating and Fixing Threats

- **What It Does**:
  - Moves high-risk threats (score ≥75) to a safe "sandbox" area.
  - Suggests fixes (e.g., patching software, isolating a server).
  - Logs actions like "Automated Remediation" in alerts.
- **Your Role**:
  - Review remediation alerts to ensure the fix worked.
  - Follow up on suggested actions (e.g., apply a patch).

### 3.4 How to Stay Informed

- **Alerts**: Check the "Alerts" tab regularly.
- **Logs**: Ask your admin for access to `logs/app.log` if you need details.
- **Reports**: Use hourly reports to track automated actions.

---

## 4. Best Practices for Analysts

- **Check Alerts Daily**: Focus on high-risk alerts (score ≥75).
- **Verify Automated Actions**:
  - Confirm blocked IPs are malicious.
  - Ensure sandboxed threats are resolved.
- **Collaborate with Admins**:
  - Report false positives (e.g., a safe IP blocked).
  - Request new assets to monitor.
- **Use Reports**:
  - Share with your team to plan defenses.
  - Track trends (e.g., new threat types).
- **Stay Updated**:
  - Attend training on new real-time-threat-intelligence features.
  - Read release notes from your admin.

---

## 6. Getting Help

- **Contact Your Admin**:
  - For login issues, new assets, or system errors.
- **Check Logs**:
  - check `logs/app.log` to troubleshoot.
- **Refer to System Manual**:
  - See `/docs/system_manual.md` for technical details.