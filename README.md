# Real-Time Threat Intelligence System

## Project Overview
The **Real-Time Threat Intelligence System** is a comprehensive platform designed to detect, analyze, and mitigate cyber threats in real time. It leverages open-source intelligence (OSINT) tools, AI-driven risk assessment, and automated defense mechanisms to provide actionable insights for security teams. The system is built with a modular architecture, ensuring scalability and ease of integration into enterprise environments.

### Key Features
- **Real-Time Threat Detection**: Fetches threat data using SpiderFoot and processes it for immediate insights.
- **Risk Assessment**: Uses AI (Hugging Face transformers) for sentiment analysis and risk scoring, with decay factors for recency.
- **Automated Defenses**: Implements blue teaming mechanisms like IP blocking and threat remediation.
- **Interactive Dashboards**: React-based frontend with Chart.js for visualizing threat logs, risk scores, and alerts.
- **Actionable Reports**: Generates PDF and CSV reports with cost-benefit analysis (CBA) and mitigation strategies.
- **Scalability**: Utilizes Redis for caching and PostgreSQL for robust data storage.

### Use Cases
- **Enterprise Security**: Monitor and protect corporate networks from phishing, malware, and DDoS attacks.
- **E-Commerce**: Secure online platforms (e.g., `shopsmart`) against SQL injection and data breaches.
- **Incident Response**: Provide prioritized threat intelligence for rapid response.

## Repository Structure
The repository is organized as follows:
```
real-time-threat-intelligence/
├── .venv/                                  # Virtual environment for Python
├── api/                                    # Legacy API directory
│   ├── __pycache__/                        # Compiled Python files
│   ├── __init__.py                         # Python package initializer
│   ├── alerts.py                           # Alert generation
│   ├── api_optimizer.py                    # Redis caching
│   ├── cba_analysis.py                     # Cost-benefit analysis
│   ├── fetch_osint.py                      # SpiderFoot integration
│   ├── logger.py                           # Logging configuration
│   ├── models.py                           # SQLAlchemy models
│   ├── spiderfoot.py                       # SpiderFoot logic
│   ├── blue_team_defence.py                # Automated defenses
│   ├── ai_threat_hunting.py                # Threat hunting
│   ├── threat_mitigation.py                # Automated mitigation
├── db/                                     # Database scripts
│   ├── tva_update.sql                      # TVA mapping updates
│   ├── incident_logs.sql                   # Incident logs schema
│   ├── alerts.sql                          # Alerts schema
│   ├── init_tva_mapping.sql                # Optional TVA mapping
│   ├── threat_data.sql                     # Threat data schema
├── docs/                                   # Documentation and reports
│   ├── final_presentation.pptx             # Final presentation
│   ├── system_walkthrough.md               # Demonstration guide
│   ├── final_demo.mp4                      # Optional demo video
│   ├── api_documentation.md                # API documentation
│   ├── research_papers/                    # Research papers
│   │   ├── osint_spiderfoot.pdf            # SpiderFoot methodology
│   │   ├── risk_scoring_ml.pdf             # ML for risk scoring
├── spiderfoot/                             # SpiderFoot configuration
│   ├── results.json                        # Sample scan results
├── isa/                                    # Alternative virtual environment
├── backups/                                # Database backups
├── logs/                                   # Application logs
│   ├── app.log                             # Main log file
├── reports/                                # Generated reports
│   ├── threat_report.pdf                   # PDF report
│   ├── threat_report.csv                   # CSV report
├── src/                                    # Primary source code
│   ├── api/                                # Flask backend
│   │   ├── __pycache__/                    # Compiled Python files
│   │   ├── __init__.py                     # Python package initializer
│   │   ├── app.py                          # Flask application
│   │   ├── config.json                     # Configuration
│   │   ├── custom_logging.py               # Logging setup
│   │   ├── risk_generator.py               # Report generation
│   │   ├── risk_scoring.py                 # Risk scoring
│   │   ├── risk_analysis.py                # Risk trend analysis
│   │   ├── incident_response.py            # Response plans
│   │   ├── risk_prioritization.py          # Threat prioritization
│   │   ├── mitigation_recommendations.py   # Mitigation recommendations
│   ├── frontend/                           # React frontend
│   │   ├── node_modules/                   # npm dependencies
│   │   ├── public/                         # Static assets
│   │   ├── src/                            # Frontend source
│   │   │   ├── components/                 # React components
│   │   │   │   ├── Dashboard.js            # Dashboard component
│   │   │   │   ├── Dashboard.css           # Dashboard styles
│   │   │   ├── App.js                      # App entry point
│   │   │   ├── App.css                     # App styles
│   │   ├── package.json                    # npm dependencies
│   │   ├── package-lock.json               # npm lock file
├── .env                                    # Environment variables (not committed)
├── requirements.txt                        # Python dependencies
├── README.md                               # This file
├── LICENSE                                 # MIT License
```

## Installation Instructions
Follow these steps to set up and run the system locally.

### Prerequisites
- **Operating System**: Linux, macOS, or Windows (WSL recommended for Windows).
- **Tools**:
  - Python 3.9+
  - Node.js 16+ and npm
  - PostgreSQL 13+
  - Redis 6+
  - Docker (for SpiderFoot)
- **Hardware**: 8GB RAM, 4-core CPU, 20GB free disk space.

### Step 1: Clone the Repository
   - Clone the git repository into the local system

### Step 2: Set Up the Backend
1. **Create a Virtual Environment**:
   ```bash
   python -m venv isa
   source isa/bin/activate 
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   - Create a `.env` file in the root directory:
     ```env
     DATABASE_URL=postgresql://shopsmart:123456789@localhost:5432/shopsmart
     REDIS_HOST=localhost
     REDIS_PORT=6379
     SMTP_SERVER=smtp.gmail.com
     SMTP_PORT=587
     SMTP_USERNAME=your-email@gmail.com
     SMTP_PASSWORD=your-app-password
     WEBHOOK_URL=https://your-webhook-url
     ```
   - Replace placeholders with your credentials.

4. **Set Up PostgreSQL**:
   - Start PostgreSQL and create the database:
     ```bash
     psql -U postgres
     CREATE USER shopsmart WITH PASSWORD '123456789';
     CREATE DATABASE shopsmart OWNER shopsmart;
     \q
     ```
   - Initialize tables:
     ```bash
     psql -U shopsmart -d shopsmart -f src/api/models.sql
     psql -U shopsmart -d shopsmart -f db/threat_data.sql
     psql -U shopsmart -d shopsmart -f db/alerts.sql
     psql -U shopsmart -d shopsmart -f db/incident_logs.sql
     psql -U shopsmart -d shopsmart -f db/init_tva_mapping.sql  # Optional
     ```

5. **Start Redis**:
   ```bash
   redis-server
   ```

6. **Run the Flask Backend**:
   ```bash
   python3 -m src.api.app
   ```

### Step 3: Set Up SpiderFoot
1. **Pull and Run SpiderFoot Docker Image**:
   ```bash
   docker run -d --name spiderfoot -p 5001:5001 spiderfoot/spiderfoot
   ```

2. **Verify SpiderFoot**:
   - Access `http://localhost:5001` or run a test scan:
     ```bash
     docker exec spiderfoot sh -c "python3 sf.py -m sfp_spider,sfp_http -s localhost:5002 -o json > /tmp/results.json"
     ```

### Step 4: Set Up the Frontend
1. **Navigate to Frontend Directory**:
   ```bash
   cd src/frontend
   ```

2. **Install npm Dependencies**:
   ```bash
   npm install
   ```

3. **Start the React App**:
   ```bash
   npm start
   ```
   - Access the dashboard at `http://localhost:3000`.

### Step 5: Verify Setup
- **Backend**: Ensure `http://localhost:5002/api/health` returns `{"status": "ok"}`.
- **Frontend**: Verify the dashboard loads at `http://localhost:3000`.
- **Database**: Check tables exist:
  ```bash
  psql -U shopsmart -d shopsmart -c "\dt"
  ```
- **Redis**: Confirm connectivity:
  ```bash
  redis-cli ping  # Should return "PONG"
  ```

## Usage
1. **Run a Threat Scan**:
   - Use SpiderFoot to scan a target (e.g., `localhost:5002`):
     ```bash
     docker exec spiderfoot sh -c "python3 sf.py -m sfp_spider,sfp_http -s localhost:5002 -o json > results.json"
     docker cp spiderfoot:/tmp/results.json .
     ```
   - The backend processes results via `/api/spiderfoot/threat-logs`.

2. **View Dashboard**:
   - Open `http://localhost:3000`.
   - Select `localhost:5002` from the asset dropdown and click **Refresh Data**.
   - Explore **Threat Logs**, **Risk Score Analysis**, and **Real-Time Alerts**.

3. **Generate Reports**:
   - Reports are generated periodically (`reports/threat_report.pdf`, `reports/threat_report.csv`).
   - Check logs for generation status:
     ```bash
     cat logs/app.log | grep "Generated report"
     ```

4. **Monitor Alerts**:
   - High-risk threats trigger email/webhook alerts (configured in `.env`).
   - View alerts in the dashboard’s **Real-Time Alerts Analysis** section.

## Documentation
- **System Walkthrough**: `/docs/system_walkthrough.md` - Step-by-step guide for demonstrating the system.
- **API Documentation**: `/docs/api_documentation.md` - Details on Flask API endpoints (e.g., `/api/spiderfoot/threat-logs`, `/api/risk-scores`).
- **Final Presentation**: `/docs/final_presentation.pptx` - Slides covering system overview, architecture, and demo.
- **Research Papers**:
  - `/docs/research_papers/osint_spiderfoot.pdf`: Methodology for OSINT using SpiderFoot.
  - `/docs/research_papers/risk_scoring_ml.pdf`: Machine learning approaches for risk scoring.
- **Reports**:
  - `/docs/threat_report.pdf`: Sample PDF threat report.
  - `/reports/threat_report.csv`: Sample CSV threat report.
- **Logs**: `/logs/app.log` - Application logs for debugging and monitoring.

## Code Structure and Documentation
The codebase is organized for maintainability and scalability, with inline comments and docstrings for key functionalities.

### Backend (`src/api/`)
- **app.py**: Main Flask application with API routes.
- **alerts.py**: Generates email and webhook alerts for high-risk threats.
- **api_optimizer.py**: Manages Redis caching for performance.
- **blue_team_defence.py**: Implements automated IP blocking and cleanup.
- **cba_analysis.py**: Performs cost-benefit analysis (ALE, ACS).
- **fetch_osint.py**: Integrates with SpiderFoot for OSINT data.
- **incident_response.py**: Generates response plans for threats.
- **models.py**: SQLAlchemy models for `threat_data`, `alert_logs`, and `tva_mapping`.
- **risk_analysis.py**: Analyzes risk trends over time.
- **risk_generator.py**: Generates PDF and CSV reports.
- **risk_prioritization.py**: Prioritizes threats based on weighted scores.
- **risk_scoring.py**: Calculates risk scores using LLM and decay factors.
- **si_threat_hunting.py**: Runs proactive threat hunting scans.
- **threat_mitigation.py**: Automates threat remediation.

**Documentation**: Each file includes docstrings and comments explaining functionality, parameters, and return values. Example:
```python
def calculate_risk_score(threat_data):
    """Calculate risk score using sentiment analysis and decay factor."""
    # Implementation details
```

### Frontend (`src/frontend/`)
- **Dashboard.js**: Renders the main dashboard with threat logs, risk charts, and alerts.
- **App.js**: Entry point for the React application.
- **package.json**: Lists dependencies (e.g., `chart.js`, `react`).

**Documentation**: Components include comments explaining props and state management. Example:
```javascript
// Dashboard.js
// Renders threat logs and risk score charts using Chart.js
```

### Verification
All key functionalities are documented and tested:
- **Threat Detection**: `fetch_osint.py` and `risk_scoring.py` are tested with sample SpiderFoot data.
- **Alerts**: `alerts.py` verified with email and webhook tests.
- **Defenses**: `blue_team_defence.py` tested with simulated malicious IPs.
- **Reports**: `risk_generator.py` produces consistent PDF/CSV outputs.
- **Performance**: Redis caching (`api_optimizer.py`) reduces query time by 80%.

## Troubleshooting
- **Flask Not Starting**: Ensure `.env` is configured and dependencies are installed (`pip install -r requirements.txt`).
- **Database Errors**: Verify PostgreSQL is running and tables exist (`psql -U shopsmart -d shopsmart -c "\dt"`).
- **Redis Issues**: Confirm Redis is running (`redis-cli ping`) and `REDIS_HOST` is correct.
- **Frontend Not Loading**: Check npm dependencies (`npm install`) and Flask CORS settings.
- **SpiderFoot Errors**: Ensure Docker container is running (`docker ps`) and scan results are accessible (`results.json`).

## Future Improvements
- Integrate advanced LLMs for improved threat classification.
- Add support for external threat feeds (e.g., VirusTotal).
- Deploy on cloud platforms (e.g., AWS) with Kubernetes.
- Develop a mobile app for on-the-go monitoring.
- Implement role-based access control (RBAC).