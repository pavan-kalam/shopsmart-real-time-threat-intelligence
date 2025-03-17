import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# Email configuration
SMTP_SERVER = "smtp.isaproject.com"  # Replace with your SMTP server
SMTP_PORT = 587  # Replace with your SMTP port
EMAIL_ADDRESS = "ISA@shopsmart.com"  # Replace with your email address
EMAIL_PASSWORD = "ISA123"  # Replace with your email password
ADMIN_EMAIL = "admin@shopsmart.com"  # Replace with the admin's email address

# Function to send email alerts
def send_alert(threat, risk_score):
    """
    Sends an email alert for high-risk threats.
    :param threat: The threat description (e.g., "SQL Injection Attack")
    :param risk_score: The risk score of the threat
    """
    try:
        # Create the email message
        msg = MIMEText(f"High-Risk Threat Detected: {threat} with Risk Score {risk_score}")
        msg["Subject"] = "Critical Cybersecurity Alert"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = ADMIN_EMAIL

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Enable TLS encryption
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)  # Log in to the email account
            server.sendmail(EMAIL_ADDRESS, ADMIN_EMAIL, msg.as_string())  # Send the email

        print(f"[{datetime.now()}] Alert sent: {threat} (Risk Score: {risk_score})")
    except Exception as e:
        print(f"[{datetime.now()}] Failed to send alert: {e}")

# Function to monitor threats and trigger alerts
def monitor_threats(threat_data):
    """
    Monitors a list of threats and sends alerts for high-risk threats.
    :param threat_data: A list of threats with risk scores
    """
    for threat in threat_data:
        if threat["risk_score"] > 20:  # Check if the risk score is above the threshold
            send_alert(threat["description"], threat["risk_score"])

# Example threat data (replace with actual data from your system)
example_threats = [
    {"description": "SQL Injection Attack", "risk_score": 25},
    {"description": "Phishing Attempt", "risk_score": 15},
    {"description": "DDoS Attack", "risk_score": 30},
]

# Example usage
if __name__ == "__main__":
    print(f"[{datetime.now()}] Starting threat monitoring...")
    monitor_threats(example_threats)  # Monitor threats and send alerts