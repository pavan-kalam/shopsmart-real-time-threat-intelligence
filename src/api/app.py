from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from fetch_osint import fetch_and_store_osint_data
import datetime
import random

# Import your API functions
from api.virustotal import fetch_virustotal_data
from api.hibp import check_email_breach
from api.abuseipdb import check_ip_abuse
from api.shodan import search_shodan

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# Configure the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Define the Assets model
class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

# Define the TVA Mapping model
class TVAMapping(db.Model):
    __tablename__ = 'tva_mapping'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'))
    threat_name = db.Column(db.String(255), nullable=False)
    vulnerability_description = db.Column(db.Text, nullable=False)
    likelihood = db.Column(db.Integer, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    risk_score = db.Column(db.Integer, default=0, nullable=False)

# User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

# User Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

# Fetch User Account Details
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "User not found"}), 404

# VirusTotal Endpoint
@app.route('/api/virustotal', methods=['GET'])
def get_virustotal_data():
    url = request.args.get('url')
    api_key = request.headers.get('API-Key')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    result = fetch_virustotal_data(api_key, url)
    return jsonify(result)

# HIBP Endpoint
@app.route('/api/hibp', methods=['GET'])
def get_hibp_data():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    breaches = check_email_breach(email)
    return jsonify(breaches)

# AbuseIPDB Endpoint
@app.route('/api/abuseipdb', methods=['GET'])
def get_abuseipdb_data():
    ip_address = request.args.get('ip_address')
    api_key = request.headers.get('API-Key')

    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    result = check_ip_abuse(api_key, ip_address)
    return jsonify(result)

# Shodan Search Endpoint
@app.route('/api/shodan', methods=['GET'])
def get_shodan_data():
    query = request.args.get('query')
    api_key = request.headers.get('API-Key')

    if not query:
        return jsonify({"error": "Query is required"}), 400

    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    result = search_shodan(api_key, query)
    return jsonify(result)

# Enhanced Dashboard API endpoints with more structured data
@app.route('/api/threat-logs', methods=['GET'])
def get_threat_logs():
    # More detailed threat logs
    threat_logs = [
        "Malware found in file example.exe from host 192.168.1.45",
        "Phishing attempt reported on example.com targeting financial credentials",
        "Suspicious IP 203.0.113.42 attempted multiple login failures",
        "Malware signature detected in network traffic from 198.51.100.23",
        "Phishing email detected with subject 'Urgent: Update your account'",
        "IP 192.0.2.18 flagged for scanning activity"
    ]
    return jsonify(threat_logs)

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    risk_scores = [92, 65, 78, 85, 45, 88]
    return jsonify(risk_scores)

@app.route('/api/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    real_time_alerts = [
        "Alert: Suspicious login attempt detected from unusual location.",
        "Alert: New malware signature detected in outbound network traffic.",
        "Alert: Unusual outbound traffic detected to known malicious IP.",
        "Alert: Multiple failed authentication attempts for admin account.",
        "Alert: Suspicious file download detected on marketing workstation."
    ]
    return jsonify(real_time_alerts)

@app.route('/api/osint', methods=['GET'])
def osint_data():
    return jsonify({"message": "OSINT data endpoint"})

@app.route('/api/fetch_osint', methods=['GET'])
def fetch_osint():
    fetch_and_store_osint_data()
    return jsonify({"message": "OSINT data fetched and stored successfully!"})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables
    app.run(debug=True, host='0.0.0.0', port=5001)
