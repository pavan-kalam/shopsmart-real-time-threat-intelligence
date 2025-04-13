# src/api/app.py
import importlib
import api.spiderfoot
importlib.reload(api.spiderfoot)
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import db, User, TvaMapping, ThreatData, AlertLog, Asset
from api.fetch_osint import fetch_osint_data
from api.spiderfoot import fetch_spiderfoot_data
from src.api.risk_analysis import analyze_risk
from src.api.risk_scoring import RiskScorer
from src.api.risk_prioritization import RiskPrioritizer
from src.api.incident_response import IncidentResponder
from api.alerts import send_alert_if_high_risk
from api.cba_analysis import suggest_mitigation
from api.api_optimizer import get_threat_data
from src.api.risk_generator import ThreatReportGenerator
from datetime import datetime, timedelta
import time
import threading
import os
import subprocess
from transformers import pipeline
from src.api.custom_logging import setup_logger

# Import new features
from api.blue_team_defence import auto_block_high_risk_ips, cleanup_old_blocks
from api.ai_threat_hunting import proactive_threat_hunt
from api.threat_mitigation import auto_remediate_threats

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)

logger = setup_logger('app')

# Initialize models and components
try:
    llm_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    logger.info("Successfully initialized Hugging Face LLM for real-time alert analysis")
except Exception as e:
    logger.error(f"Failed to initialize LLM classifier: {str(e)}")
    llm_classifier = None

try:
    generator = pipeline("text-generation", model="gpt2")
    logger.info("Successfully initialized Hugging Face text generation model (gpt2)")
except Exception as e:
    logger.error(f"Failed to initialize text generation model: {str(e)}")
    generator = None

risk_scorer = RiskScorer()
risk_prioritizer = RiskPrioritizer()
incident_responder = IncidentResponder()
lock = threading.Lock()

# Use the correct pgAdmin 4 pg_dump path
PG_DUMP_PATH = "/Applications/pgAdmin 4.app/Contents/SharedSupport/pg_dump"

def backup_database():
    backup_path = f"backups/shopsmart_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.sql"
    os.makedirs('backups', exist_ok=True)
    try:
        subprocess.run([PG_DUMP_PATH, "-U", "shopsmart", "-d", "shopsmart", "-f", backup_path], check=True, env={"PGPASSWORD": "123456789"})
        logger.info(f"Database backed up to {backup_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup failed: {str(e)}")
        raise  # Re-raise to halt report generation if backup fails


def generate_periodic_reports():
    logger.info("Starting periodic report generation thread")
    report_generator = ThreatReportGenerator()
    while True:
        try:
            logger.debug("Beginning report generation cycle")
            with app.app_context():
                backup_database()
                reports = report_generator.generate_reports()
                logger.info(f"Periodic reports generated: PDF={reports['pdf']}, CSV={reports['csv']}")
        except Exception as e:
            logger.error(f"Periodic report generation failed: {str(e)}", exc_info=True)
        time.sleep(3600)  # Hourly

# Start periodic reporting
logger.info("Launching report generation thread")
threading.Thread(target=generate_periodic_reports, daemon=True).start()

def start_defensive_mechanisms():
    """Run background defensive mechanisms."""
    logger.info("Starting defensive mechanisms thread")
    while True:
        try:
            with app.app_context():
                auto_block_high_risk_ips()
                cleanup_old_blocks()
                proactive_threat_hunt()
                auto_remediate_threats()
            logger.info("Completed defensive mechanisms cycle")
        except Exception as e:
            logger.error(f"Defensive mechanisms failed: {str(e)}")
        time.sleep(1800)  # Run every 5 minutes(300)

with app.app_context():
    db.create_all()
    threading.Thread(target=generate_periodic_reports, daemon=True).start()
    threading.Thread(target=start_defensive_mechanisms, daemon=True).start()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User registered: {username}")
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to register user: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        logger.info(f"User logged in: {username}")
        return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
    else:
        logger.warning(f"Failed login attempt for {username}")
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    else:
        logger.warning(f"User not found: {user_id}")
        return jsonify({"error": "User not found"}), 404

@app.route('/api/assets', methods=['GET'])
def get_assets():
    try:
        assets = Asset.query.all()
        assets_list = [
            {"id": asset.id, "name": asset.name, "type": asset.type, "identifier": asset.identifier}
            for asset in assets
        ]
        logger.info(f"Fetched {len(assets_list)} assets")
        return jsonify(assets_list), 200
    except Exception as e:
        logger.error(f"Failed to fetch assets: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/spiderfoot/threat-logs', methods=['GET'])
def get_threat_logs():
    with lock:
        try:
            start_time = time.time()
            query = request.args.get('query', 'localhost:5002')
            osint_data = get_threat_data(query)
            logger.info(f"get_threat_data for query '{query}' took {time.time() - start_time:.2f} seconds")
            if not isinstance(osint_data, dict) or 'events' not in osint_data:
                logger.error(f"Invalid OSINT data structure: {osint_data}")
                raise ValueError("Invalid OSINT data structure received")
            events = osint_data.get('events', [])
            if not events:
                logger.warning("No events returned from SpiderFoot")
                events = [
                    {
                        "description": f"SpiderFoot failed for query '{query}'",
                        "threat_type": "Error",
                        "risk_score": 75
                    }
                ]
            tva_mappings = [
                {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
                for tva in TvaMapping.query.all()
            ]
            threats_for_scoring = [
                {
                    "description": event.get("description", "Unknown"),
                    "likelihood": next((tva["likelihood"] for tva in tva_mappings if tva["threat_name"] == event.get("threat_type", "Other")), 3),
                    "impact": next((tva["impact"] for tva in tva_mappings if tva["threat_name"] == event.get("threat_type", "Other")), 3),
                    "created_at": datetime.utcnow()
                }
                for event in events
            ]
            risk_scores = risk_scorer.analyze_risk(threats_for_scoring)

            # Bulk fetch existing threats
            descriptions = [event.get('description', 'Unknown') for event in events]
            existing_threats = {t.description: t for t in ThreatData.query.filter(ThreatData.description.in_(descriptions)).all()}
            threats_with_metadata = []
            processed_threats = set()

            for event, risk_score in zip(events, risk_scores):
                desc = event.get('description', 'Unknown')
                if desc in processed_threats:
                    continue
                processed_threats.add(desc)
                threat_entry = existing_threats.get(desc)
                if not threat_entry:
                    threat_entry = ThreatData(
                        description=desc,
                        threat_type=event.get('threat_type', 'Other'),
                        risk_score=risk_score,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(threat_entry)
                    created_at = datetime.utcnow()
                    logger.info(f"Inserted new threat into threat_data: {desc}")
                else:
                    created_at = threat_entry.created_at
                threats_with_metadata.append({
                    'description': desc,
                    'threat_type': event.get('threat_type', 'Other'),
                    'risk_score': risk_score,
                    'created_at': created_at
                })

            prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
            threat_logs = []
            for threat in prioritized_threats[:10]:
                send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
                response_plan = incident_responder.generate_response_plan(threat)
                cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
                threat_logs.append({
                    'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
                    'response_plan': response_plan,
                    'cba': cba_info
                })
            db.session.commit()
            logger.info(f"Returning {len(threat_logs)} threat logs for query '{query}'")
            return jsonify(threat_logs), 200
        except Exception as e:
            logger.error(f"Failed to fetch threat logs: {str(e)}")
            db.session.rollback()
            return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

def get_threat_data(query, modules="sfp_spider,sfp_http"):
    try:
        spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
        return spiderfoot_data
    except Exception as e:
        logger.error(f"Error in get_threat_data: {str(e)}")
        return {
            "events": [
                {
                    "description": f"SpiderFoot failed for query '{query}'",
                    "threat_type": "Error",
                    "risk_score": 75
                }
            ]
        }

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    try:
        query = request.args.get('query', 'localhost:5002')
        osint_data = get_threat_data(query)
        threats_for_scoring = [
            {
                "description": event.get("description", "Unknown"),
                "likelihood": 3,
                "impact": 3,
                "created_at": datetime.utcnow()
            }
            for event in osint_data.get("events", [])
        ]
        risk_scores = risk_scorer.analyze_risk(threats_for_scoring)
        logger.info(f"Risk scores for query '{query}': {risk_scores}")
        return jsonify(risk_scores), 200
    except Exception as e:
        logger.error(f"Failed to fetch risk scores: {str(e)}")
        return jsonify([50, 75, 90]), 200

@app.route('/api/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    try:
        logger.info("Starting real-time alerts fetch")
        asset_name = request.args.get('query', '')
        asset = Asset.query.filter_by(name=asset_name).first()
        query = asset.identifier if asset and asset.identifier else asset_name
        logger.info(f"Fetching real-time alerts for query: '{query}'")
        alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
        logger.info(f"Fetched {len(alerts)} alerts from threat_data table")

        filtered_alerts = [
            alert for alert in alerts
            if query.lower() in alert.description.lower()
        ] if query else alerts
        if not filtered_alerts:
            logger.warning(f"No alerts matched query '{query}', returning all alerts")
            filtered_alerts = alerts

        alerts_list = []
        for alert in filtered_alerts:
            try:
                threat_info = {
                    "description": alert.description,
                    "risk_score": alert.risk_score,
                    "threat_type": alert.threat_type
                }
                base_response_plan = incident_responder.generate_response_plan(threat_info)
                mitigation_strategies = base_response_plan["mitigation_strategies"]
                response_steps = base_response_plan["response_steps"]
                if generator:
                    mitigation_prompt = f"Generate mitigation strategies for: {alert.description}, Type: {alert.threat_type}, Risk: {alert.risk_score}."
                    mitigation_response = generator(mitigation_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
                    mitigation_strategies = [s.strip() for s in mitigation_response.split('\n') if s.strip()][:3]
                    response_prompt = f"Generate response steps for: {alert.description}, Type: {alert.threat_type}, Risk: {alert.risk_score}."
                    response_response = generator(response_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
                    response_steps = [s.strip() for s in response_response.split('\n') if s.strip()][:3]

                llm_insights = {}
                if llm_classifier:
                    labels = ["Low Severity", "Medium Severity", "High Severity"]
                    result = llm_classifier(
                        alert.description,
                        candidate_labels=labels,
                        hypothesis_template="This alert indicates a {} threat."
                    )
                    llm_insights = {
                        "severity": result["labels"][0],
                        "confidence": round(result["scores"][0], 2),
                        "suggested_action": suggest_action(result["labels"][0])
                    }
                else:
                    llm_insights = {"severity": "Unknown", "confidence": 0, "suggested_action": "Manual review required"}

                response_plan = {
                    "threat_type": alert.threat_type,
                    "description": alert.description,
                    "priority": base_response_plan["priority"],
                    "mitigation_strategies": mitigation_strategies,
                    "response_steps": response_steps
                }

                alerts_list.append({
                    "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
                    "response_plan": response_plan,
                    "llm_insights": llm_insights
                })
            except Exception as e:
                logger.error(f"Failed to process alert {alert.description}: {str(e)}")
                response_plan = {
                    "threat_type": alert.threat_type,
                    "description": alert.description,
                    "priority": "Medium",
                    "mitigation_strategies": ["Unable to generate strategies due to error"],
                    "response_steps": ["Unable to generate steps due to error"]
                }
                alerts_list.append({
                    "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
                    "response_plan": response_plan,
                    "llm_insights": {"severity": "Unknown", "confidence": 0, "suggested_action": "Manual review required"}
                })
        logger.info(f"Returning {len(alerts_list)} real-time alerts for query '{query}'")
        return jsonify(alerts_list), 200
    except Exception as e:
        logger.error(f"Failed to fetch real-time alerts: {str(e)}")
        db.session.rollback()
        return jsonify([]), 200

@app.route('/api/generate-report', methods=['GET'])
def generate_report():
    backup_database()
    generator = ThreatReportGenerator()
    format = request.args.get('format', 'pdf')
    try:
        if format == 'pdf':
            path = generator.generate_pdf()
            return send_file(path, as_attachment=True, download_name=os.path.basename(path))
        elif format == 'csv':
            path = generator.generate_csv()
            return send_file(path, as_attachment=True, download_name=os.path.basename(path))
        else:
            return jsonify({"error": "Invalid format"}), 400
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")
        return jsonify({"error": str(e)}), 500

def suggest_action(severity):
    actions = {
        "Low Severity": "Monitor the situation and log for future reference.",
        "Medium Severity": "Investigate the alert and apply basic mitigation steps.",
        "High Severity": "Escalate immediately and initiate full incident response."
    }
    return actions.get(severity, "Manual review required")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
    logger.info("Application is running on port 5002")



# # src/api/app.py
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)
# from flask import Flask, jsonify, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog, Asset
# from api.fetch_osint import fetch_osint_data
# from api.spiderfoot import fetch_spiderfoot_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_scoring import RiskScorer
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from src.api.risk_generator import ThreatReportGenerator
# from datetime import datetime, timedelta
# import time
# import threading
# import os
# import subprocess
# from transformers import pipeline
# from src.api.custom_logging import setup_logger

# app = Flask(__name__)
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)
# migrate = Migrate(app, db)

# logger = setup_logger('app')

# # Initialize models and components
# try:
#     llm_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
#     logger.info("Successfully initialized Hugging Face LLM for real-time alert analysis")
# except Exception as e:
#     logger.error(f"Failed to initialize LLM classifier: {str(e)}")
#     llm_classifier = None

# try:
#     generator = pipeline("text-generation", model="gpt2")
#     logger.info("Successfully initialized Hugging Face text generation model (gpt2)")
# except Exception as e:
#     logger.error(f"Failed to initialize text generation model: {str(e)}")
#     generator = None

# risk_scorer = RiskScorer()
# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# # Use the correct pgAdmin 4 pg_dump path
# PG_DUMP_PATH = "/Applications/pgAdmin 4.app/Contents/SharedSupport/pg_dump"

# def backup_database():
#     backup_path = f"backups/shopsmart_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.sql"
#     os.makedirs('backups', exist_ok=True)
#     try:
#         subprocess.run([PG_DUMP_PATH, "-U", "shopsmart", "-d", "shopsmart", "-f", backup_path], check=True, env={"PGPASSWORD": "123456789"})
#         logger.info(f"Database backed up to {backup_path}")
#     except subprocess.CalledProcessError as e:
#         logger.error(f"Backup failed: {str(e)}")
#         raise  # Re-raise to halt report generation if backup fails

# def generate_periodic_reports():
#     logger.info("Starting periodic report generation thread")
#     report_generator = ThreatReportGenerator()
#     while True:
#         try:
#             logger.debug("Beginning report generation cycle")
#             with app.app_context():
#                 backup_database()
#                 report_path = report_generator.generate_pdf()
#                 logger.info(f"Periodic report generated: {report_path}")
#         except Exception as e:
#             logger.error(f"Periodic report generation failed: {str(e)}", exc_info=True)
#         logger.debug("Sleeping for 1 minute (testing)")
#         time.sleep(3600)  # 1 minute for testing; revert to 3600 for hourly

# # Start periodic reporting
# logger.info("Launching report generation thread")
# threading.Thread(target=generate_periodic_reports, daemon=True).start()

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400
#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)
#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         logger.info(f"User registered: {username}")
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         logger.info(f"User logged in: {username}")
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         logger.warning(f"Failed login attempt for {username}")
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         logger.warning(f"User not found: {user_id}")
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {"id": asset.id, "name": asset.name, "type": asset.type, "identifier": asset.identifier}
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             start_time = time.time()
#             query = request.args.get('query', 'localhost:5002')
#             osint_data = get_threat_data(query)
#             logger.info(f"get_threat_data for query '{query}' took {time.time() - start_time:.2f} seconds")
#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")
#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning("No events returned from SpiderFoot")
#                 events = [
#                     {
#                         "description": f"SpiderFoot failed for query '{query}'",
#                         "threat_type": "Error",
#                         "risk_score": 75
#                     }
#                 ]
#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]
#             threats_for_scoring = [
#                 {
#                     "description": event.get("description", "Unknown"),
#                     "likelihood": next((tva["likelihood"] for tva in tva_mappings if tva["threat_name"] == event.get("threat_type", "Other")), 3),
#                     "impact": next((tva["impact"] for tva in tva_mappings if tva["threat_name"] == event.get("threat_type", "Other")), 3),
#                     "created_at": datetime.utcnow()
#                 }
#                 for event in events
#             ]
#             risk_scores = risk_scorer.analyze_risk(threats_for_scoring)

#             # Bulk fetch existing threats
#             descriptions = [event.get('description', 'Unknown') for event in events]
#             existing_threats = {t.description: t for t in ThreatData.query.filter(ThreatData.description.in_(descriptions)).all()}
#             threats_with_metadata = []
#             processed_threats = set()

#             for event, risk_score in zip(events, risk_scores):
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)
#                 threat_entry = existing_threats.get(desc)
#                 if not threat_entry:
#                     threat_entry = ThreatData(
#                         description=desc,
#                         threat_type=event.get('threat_type', 'Other'),
#                         risk_score=risk_score,
#                         created_at=datetime.utcnow()
#                     )
#                     db.session.add(threat_entry)
#                     created_at = datetime.utcnow()
#                     logger.info(f"Inserted new threat into threat_data: {desc}")
#                 else:
#                     created_at = threat_entry.created_at
#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []
#             for threat in prioritized_threats[:10]:
#                 send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })
#             db.session.commit()
#             logger.info(f"Returning {len(threat_logs)} threat logs for query '{query}'")
#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             db.session.rollback()
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         return {
#             "events": [
#                 {
#                     "description": f"SpiderFoot failed for query '{query}'",
#                     "threat_type": "Error",
#                     "risk_score": 75
#                 }
#             ]
#         }

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         query = request.args.get('query', 'localhost:5002')
#         osint_data = get_threat_data(query)
#         threats_for_scoring = [
#             {
#                 "description": event.get("description", "Unknown"),
#                 "likelihood": 3,
#                 "impact": 3,
#                 "created_at": datetime.utcnow()
#             }
#             for event in osint_data.get("events", [])
#         ]
#         risk_scores = risk_scorer.analyze_risk(threats_for_scoring)
#         logger.info(f"Risk scores for query '{query}': {risk_scores}")
#         return jsonify(risk_scores), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         logger.info("Starting real-time alerts fetch")
#         asset_name = request.args.get('query', '')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name
#         logger.info(f"Fetching real-time alerts for query: '{query}'")
#         alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
#         logger.info(f"Fetched {len(alerts)} alerts from threat_data table")

#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.description.lower()
#         ] if query else alerts
#         if not filtered_alerts:
#             logger.warning(f"No alerts matched query '{query}', returning all alerts")
#             filtered_alerts = alerts

#         alerts_list = []
#         for alert in filtered_alerts:
#             try:
#                 threat_info = {
#                     "description": alert.description,
#                     "risk_score": alert.risk_score,
#                     "threat_type": alert.threat_type
#                 }
#                 base_response_plan = incident_responder.generate_response_plan(threat_info)
#                 mitigation_strategies = base_response_plan["mitigation_strategies"]
#                 response_steps = base_response_plan["response_steps"]
#                 if generator:
#                     mitigation_prompt = f"Generate mitigation strategies for: {alert.description}, Type: {alert.threat_type}, Risk: {alert.risk_score}."
#                     mitigation_response = generator(mitigation_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
#                     mitigation_strategies = [s.strip() for s in mitigation_response.split('\n') if s.strip()][:3]
#                     response_prompt = f"Generate response steps for: {alert.description}, Type: {alert.threat_type}, Risk: {alert.risk_score}."
#                     response_response = generator(response_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
#                     response_steps = [s.strip() for s in response_response.split('\n') if s.strip()][:3]

#                 llm_insights = {}
#                 if llm_classifier:
#                     labels = ["Low Severity", "Medium Severity", "High Severity"]
#                     result = llm_classifier(
#                         alert.description,
#                         candidate_labels=labels,
#                         hypothesis_template="This alert indicates a {} threat."
#                     )
#                     llm_insights = {
#                         "severity": result["labels"][0],
#                         "confidence": round(result["scores"][0], 2),
#                         "suggested_action": suggest_action(result["labels"][0])
#                     }
#                 else:
#                     llm_insights = {"severity": "Unknown", "confidence": 0, "suggested_action": "Manual review required"}

#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "priority": base_response_plan["priority"],
#                     "mitigation_strategies": mitigation_strategies,
#                     "response_steps": response_steps
#                 }

#                 alerts_list.append({
#                     "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
#                     "response_plan": response_plan,
#                     "llm_insights": llm_insights
#                 })
#             except Exception as e:
#                 logger.error(f"Failed to process alert {alert.description}: {str(e)}")
#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "priority": "Medium",
#                     "mitigation_strategies": ["Unable to generate strategies due to error"],
#                     "response_steps": ["Unable to generate steps due to error"]
#                 }
#                 alerts_list.append({
#                     "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
#                     "response_plan": response_plan,
#                     "llm_insights": {"severity": "Unknown", "confidence": 0, "suggested_action": "Manual review required"}
#                 })
#         logger.info(f"Returning {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         db.session.rollback()
#         return jsonify([]), 200

# @app.route('/api/generate-report', methods=['GET'])
# def generate_report():
#     backup_database()
#     generator = ThreatReportGenerator()
#     format = request.args.get('format', 'pdf')
#     try:
#         if format == 'pdf':
#             path = generator.generate_pdf()
#         elif format == 'csv':
#             path = generator.generate_csv()
#         else:
#             return jsonify({"error": "Invalid format"}), 400
#         logger.info(f"Manual report generated: {path}")
#         return jsonify({"message": "Report generated", "path": path}), 200
#     except Exception as e:
#         logger.error(f"Failed to generate report: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# def suggest_action(severity):
#     actions = {
#         "Low Severity": "Monitor the situation and log for future reference.",
#         "Medium Severity": "Investigate the alert and apply basic mitigation steps.",
#         "High Severity": "Escalate immediately and initiate full incident response."
#     }
#     return actions.get(severity, "Manual review required")

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5002)
#     logger.info("Application is running on port 5002")
