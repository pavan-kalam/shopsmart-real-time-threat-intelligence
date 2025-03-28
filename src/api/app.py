# src/api/app.py
import importlib
import api.spiderfoot
importlib.reload(api.spiderfoot)

from flask import Flask, jsonify, request
import logging
from api.logger import logger
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import db, User, TvaMapping, ThreatData, AlertLog
from api.fetch_osint import fetch_osint_data
from api.spiderfoot import fetch_spiderfoot_data
from src.api.risk_analysis import analyze_risk
from src.api.risk_prioritization import RiskPrioritizer
from src.api.incident_response import IncidentResponder
from api.alerts import send_alert_if_high_risk
from api.cba_analysis import suggest_mitigation
from api.api_optimizer import get_threat_data
from datetime import datetime, timedelta
from time import time
import threading
from api.models import db, Asset
from transformers import pipeline  # For LLM integration

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# Enable CORS for frontend
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)

# Initialize LLM for zero-shot classification (severity analysis)
try:
    llm_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    logger.info("Successfully initialized Hugging Face LLM for real-time alert analysis")
except Exception as e:
    logger.error(f"Failed to initialize LLM classifier: {str(e)}")
    llm_classifier = None

# Initialize text generation model for mitigation strategies and response steps
try:
    generator = pipeline("text-generation", model="gpt2")
    logger.info("Successfully initialized Hugging Face text generation model (gpt2)")
except Exception as e:
    logger.error(f"Failed to initialize text generation model: {str(e)}")
    generator = None

risk_prioritizer = RiskPrioritizer()
incident_responder = IncidentResponder()
lock = threading.Lock()

with app.app_context():
    db.create_all()

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
        return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/api/assets', methods=['GET'])
def get_assets():
    try:
        assets = Asset.query.all()
        assets_list = [
            {
                "id": asset.id,
                "name": asset.name,
                "type": asset.type,
                "identifier": asset.identifier
            }
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
            start_time = time()
            query = request.args.get('query', 'localhost:5002')
            osint_data = get_threat_data(query)
            logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
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
            threat_descriptions = [event.get("description", "Unknown") for event in events]
            risk_scores = analyze_risk(threat_descriptions)
            tva_mappings = [
                {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
                for tva in TvaMapping.query.all()
            ]
            processed_threats = set()
            threats_with_metadata = []
            for event, risk_score in zip(events, risk_scores):
                desc = event.get('description', 'Unknown')
                if desc in processed_threats:
                    continue
                processed_threats.add(desc)
                threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
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
        threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
        risk_scores = analyze_risk(threat_descriptions)
        return jsonify(risk_scores if risk_scores else [50, 75, 90])
    except Exception as e:
        logger.error(f"Failed to fetch risk scores: {str(e)}")
        return jsonify([50, 75, 90]), 200

# Combined endpoint with previous and current functionality
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

        # Relaxed filtering: If query doesn't match, return all alerts
        filtered_alerts = [
            alert for alert in alerts
            if query.lower() in alert.description.lower()
        ]
        if not filtered_alerts:
            logger.warning(f"No alerts matched query '{query}', returning all alerts")
            filtered_alerts = alerts

        logger.info(f"Filtered {len(filtered_alerts)} alerts after applying query filter")

        alerts_list = []
        for alert in filtered_alerts:
            try:
                # Existing IncidentResponder response plan
                threat_info = {
                    "description": alert.description,
                    "risk_score": alert.risk_score,
                    "threat_type": alert.threat_type
                }
                base_response_plan = incident_responder.generate_response_plan(threat_info)

                # Text generation for mitigation strategies and response steps
                mitigation_strategies = base_response_plan["mitigation_strategies"]
                response_steps = base_response_plan["response_steps"]
                if generator:
                    mitigation_prompt = (
                        f"Generate mitigation strategies for a cybersecurity threat: "
                        f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
                        f"Provide a list of strategies."
                    )
                    mitigation_response = generator(mitigation_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
                    mitigation_strategies = [s.strip() for s in mitigation_response.split('\n') if s.strip()][:3]

                    response_prompt = (
                        f"Generate response steps for a cybersecurity threat: "
                        f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
                        f"Provide a list of steps."
                    )
                    response_response = generator(response_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
                    response_steps = [s.strip() for s in response_response.split('\n') if s.strip()][:3]

                # LLM severity analysis
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

                # Construct combined response plan
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
                    "priority": "Medium",  # Default priority on error
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

# Helper function for LLM suggested actions
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







# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from api.fetch_osint import fetch_osint_data
# from src.api.risk_analysis import analyze_risk
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from datetime import datetime
# from time import time
# from datetime import timedelta

# logging.basicConfig(level=logging.INFO)

# app = Flask(__name__)
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)

# # Initialize risk prioritizer and incident responder
# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400

#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password=hashed_password)

#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400

#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     try:
#         start_time = time()
#         osint_data = fetch_osint_data()
#         logger.info(f"fetch_osint_data took {time() - start_time:.2f} seconds")
        
#         if not isinstance(osint_data, dict) or 'events' not in osint_data:
#             logger.error("Invalid OSINT data structure received.")
#             return jsonify({"error": "Invalid OSINT data structure."}), 500

#         events = osint_data['events']
#         threat_descriptions = [event["description"] for event in events]
#         risk_scores = analyze_risk(threat_descriptions)
        
#         # Fetch TVA mappings
#         tva_mappings = [
#             {
#                 'threat_name': tva.threat_name,
#                 'likelihood': tva.likelihood,
#                 'impact': tva.impact
#             } for tva in TvaMapping.query.all()
#         ]

#         # Fetch threat data from the database for recency
#         threats_with_metadata = []
#         for event, risk_score in zip(events, risk_scores):
#             threat_entry = ThreatData.query.filter_by(description=event['description']).order_by(ThreatData.created_at.desc()).first()
#             created_at = threat_entry.created_at if threat_entry else None
#             threats_with_metadata.append({
#                 'description': event['description'],
#                 'threat_type': event['threat_type'],
#                 'risk_score': risk_score,
#                 'created_at': created_at
#             })

#         # Prioritize threats
#         prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)

#         # Generate response plans
#         threat_logs = []
#         for threat in prioritized_threats:
#             response_plan = incident_responder.generate_response_plan(threat)
#             threat_logs.append({
#                 'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                 'response_plan': response_plan
#             })

#         return jsonify(threat_logs if threat_logs else [{"log": "No threat logs available", "response_plan": {}}])
#     except Exception as e:
#         logger.error(f"Failed to fetch threat logs: {str(e)}")
#         return jsonify([{"log": "Hardcoded Threat Log 1", "response_plan": {}}, {"log": "Hardcoded Threat Log 2", "response_plan": {}}]), 200

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = fetch_osint_data()
#         threat_descriptions = [event["description"] for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90])
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         # Fetch recent alerts from threat_data (last 24 hours)
#         alerts = ThreatData.query.filter(ThreatData.created_at >= datetime.now() - timedelta(hours=24)).all()
#         alert_threats = [
#             {
#                 'description': alert.description,
#                 'threat_type': alert.threat_type,
#                 'risk_score': alert.risk_score,
#                 'created_at': alert.created_at
#             } for alert in alerts
#         ]

#         # Fetch TVA mappings
#         tva_mappings = [
#             {
#                 'threat_name': tva.threat_name,
#                 'likelihood': tva.likelihood,
#                 'impact': tva.impact
#             } for tva in TvaMapping.query.all()
#         ]

#         # Prioritize alerts
#         prioritized_alerts = risk_prioritizer.prioritize_threats(alert_threats, tva_mappings)

#         # Generate response plans
#         real_time_alerts = []
#         for alert in prioritized_alerts:
#             response_plan = incident_responder.generate_response_plan(alert)
#             real_time_alerts.append({
#                 'alert': f"{alert['description']} (Priority: {alert['priority_score']:.2f})",
#                 'response_plan': response_plan
#             })

#         return jsonify(real_time_alerts if real_time_alerts else [
#             {"alert": "No real-time alerts available", "response_plan": {}}
#         ])
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         return jsonify([
#             {"alert": "Hardcoded Alert 1", "response_plan": {}},
#             {"alert": "Hardcoded Alert 2", "response_plan": {}}
#         ]), 200

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True, host='0.0.0.0', port=5002)
#     logger.info("Application is running on port 5002")