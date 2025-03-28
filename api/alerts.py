# # api/alerts.py
# import smtplib
# import logging
# import os
# import requests
# from email.mime.text import MIMEText
# from dotenv import load_dotenv
# from api.models import db, AlertLog
# from datetime import datetime, timedelta

# load_dotenv()

# SMTP_SERVER = os.getenv('SMTP_SERVER')
# SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
# SMTP_USER = os.getenv('SMTP_USER')
# SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
# EMAIL_FROM = os.getenv('EMAIL_FROM')
# EMAIL_TO = os.getenv('EMAIL_TO')
# WEBHOOK_URL = os.getenv('WEBHOOK_URL')

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger('alerts')

# last_alert_time = {}

# def send_alert_if_high_risk(threat_description, risk_score, threat_type="Other"):
#     global last_alert_time
#     now = datetime.utcnow()
#     if threat_description in last_alert_time:
#         if (now - last_alert_time[threat_description]).total_seconds() < 300:
#             return
#     last_alert_time[threat_description] = now
#     if risk_score > 20:
#         recent_alert = AlertLog.query.filter(
#             AlertLog.threat == threat_description,
#             AlertLog.risk_score == risk_score,
#             AlertLog.alert_type == 'High Risk',
#             AlertLog.created_at >= now - timedelta(hours=24)
#         ).first()
#         if recent_alert:
#             logger.info(f"Skipping duplicate alert for {threat_description}")
#             return
#         send_email_alert(threat_description, risk_score)
#         send_webhook_alert(threat_description, risk_score)
#         alert = AlertLog(
#             threat=threat_description,
#             alert_type='High Risk',
#             risk_score=risk_score,
#             threat_type=threat_type,  # Include threat_type
#             created_at=now
#         )
#         db.session.add(alert)
#         db.session.commit()
#         logger.info(f"New alert logged: {threat_description}")

# def send_email_alert(threat_description, risk_score):
#     subject = "High Risk Alert"
#     body = f"Threat: {threat_description}\nRisk Score: {risk_score}"
#     msg = MIMEText(body)
#     msg['Subject'] = subject
#     msg['From'] = EMAIL_FROM
#     msg['To'] = EMAIL_TO
#     try:
#         with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
#             server.starttls()
#             server.login(SMTP_USER, SMTP_PASSWORD)
#             server.send_message(msg)
#         logger.info(f"Email alert sent for {threat_description}")
#     except Exception as e:
#         logger.error(f"Failed to send email alert: {str(e)}")

# def send_webhook_alert(threat_description, risk_score):
#     if not WEBHOOK_URL:
#         return
#     payload = {"threat": threat_description, "risk_score": risk_score}
#     try:
#         response = requests.post(WEBHOOK_URL, json=payload)
#         response.raise_for_status()
#         logger.info(f"Webhook alert sent for {threat_description}")
#     except Exception as e:
#         logger.error(f"Failed to send webhook alert: {str(e)}")


# api/alerts.py
import smtplib
import logging
import os
import requests
from email.mime.text import MIMEText
from dotenv import load_dotenv
from api.models import db, AlertLog
from datetime import datetime, timedelta

load_dotenv()

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_FROM')
EMAIL_TO = os.getenv('EMAIL_TO')
WEBHOOK_URL = os.getenv('WEBHOOK_URL')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('alerts')

last_alert_time = {}

def send_alert_if_high_risk(threat_description, risk_score, threat_type="Other"):
    global last_alert_time
    now = datetime.utcnow()
    # Temporarily disable throttling for debugging
    # if threat_description in last_alert_time:
    #     if (now - last_alert_time[threat_description]).total_seconds() < 300:
    #         return
    # last_alert_time[threat_description] = now
    if risk_score > 20:
        # Temporarily disable duplicate check for debugging
        # recent_alert = AlertLog.query.filter(
        #     AlertLog.threat == threat_description,
        #     AlertLog.risk_score == risk_score,
        #     AlertLog.alert_type == 'High Risk',
        #     AlertLog.created_at >= now - timedelta(hours=24)
        # ).first()
        # if recent_alert:
        #     logger.info(f"Skipping duplicate alert for {threat_description}")
        #     return
        try:
            send_email_alert(threat_description, risk_score)
            send_webhook_alert(threat_description, risk_score)
            alert = AlertLog(
                threat=threat_description,
                alert_type='High Risk',
                risk_score=risk_score,
                threat_type=threat_type,
                created_at=now
            )
            db.session.add(alert)
            db.session.commit()
            logger.info(f"New alert logged: {threat_description}")
        except Exception as e:
            logger.error(f"Failed to log alert for {threat_description}: {str(e)}")
            db.session.rollback()

def send_email_alert(threat_description, risk_score):
    subject = "High Risk Alert"
    body = f"Threat: {threat_description}\nRisk Score: {risk_score}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email alert sent for {threat_description}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {str(e)}")

def send_webhook_alert(threat_description, risk_score):
    if not WEBHOOK_URL:
        return
    payload = {"threat": threat_description, "risk_score": risk_score}
    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        response.raise_for_status()
        logger.info(f"Webhook alert sent for {threat_description}")
    except Exception as e:
        logger.error(f"Failed to send webhook alert: {str(e)}")

# # api/alerts.py
# import smtplib
# import logging
# import os
# import requests
# from email.mime.text import MIMEText
# from dotenv import load_dotenv
# from api.models import db, AlertLog
# from datetime import datetime, timedelta
# from ratelimit import limits, sleep_and_retry
# from requests.exceptions import HTTPError

# load_dotenv()

# SMTP_SERVER = os.getenv('SMTP_SERVER')
# SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
# SMTP_USER = os.getenv('SMTP_USER')
# SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
# EMAIL_FROM = os.getenv('EMAIL_FROM')
# EMAIL_TO = os.getenv('EMAIL_TO')
# WEBHOOK_URL = os.getenv('WEBHOOK_URL')

# # Rate limit: 100 requests per minute (adjust based on webhook.site's actual limit)
# CALLS_PER_MINUTE = 100
# PERIOD = 60  # 60 seconds

# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('alerts.log'),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger('alerts')

# last_alert_time = {}

# def send_alert_if_high_risk(threat_description, risk_score, threat_type="Other"):
#     global last_alert_time
#     now = datetime.utcnow()
#     if threat_description in last_alert_time:
#         if (now - last_alert_time[threat_description]).total_seconds() < 300:
#             logger.info(f"Skipping alert for {threat_description} due to recent alert within 5 minutes")
#             return
#     last_alert_time[threat_description] = now
#     if risk_score > 20:
#         recent_alert = AlertLog.query.filter(
#             AlertLog.threat == threat_description,
#             AlertLog.risk_score == risk_score,
#             AlertLog.alert_type == 'High Risk',
#             AlertLog.created_at >= now - timedelta(hours=24)
#         ).first()
#         if recent_alert:
#             logger.info(f"Skipping duplicate alert for {threat_description}")
#             return
#         send_email_alert(threat_description, risk_score)
#         send_webhook_alert(threat_description, risk_score)
#         alert = AlertLog(
#             threat=threat_description,
#             alert_type='High Risk',
#             risk_score=risk_score,
#             threat_type=threat_type,
#             created_at=now
#         )
#         db.session.add(alert)
#         db.session.commit()
#         logger.info(f"New alert logged: {threat_description}")

# def send_email_alert(threat_description, risk_score):
#     subject = "High Risk Alert"
#     body = f"Threat: {threat_description}\nRisk Score: {risk_score}"
#     msg = MIMEText(body)
#     msg['Subject'] = subject
#     msg['From'] = EMAIL_FROM
#     msg['To'] = EMAIL_TO
#     try:
#         with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
#             server.starttls()
#             server.login(SMTP_USER, SMTP_PASSWORD)
#             server.send_message(msg)
#         logger.info(f"Email alert sent for {threat_description}")
#     except Exception as e:
#         logger.error(f"Failed to send email alert: {str(e)}")

# @sleep_and_retry
# @limits(calls=CALLS_PER_MINUTE, period=PERIOD)
# def send_webhook_alert(threat_description, risk_score, max_retries=3, backoff_factor=2):
#     if not WEBHOOK_URL:
#         logger.warning("WEBHOOK_URL not set, skipping webhook alert")
#         return
#     payload = {"threat": threat_description, "risk_score": risk_score}
#     attempt = 0
#     while attempt < max_retries:
#         try:
#             response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
#             response.raise_for_status()
#             logger.info(f"Webhook alert sent for {threat_description}")
#             return True
#         except HTTPError as e:
#             if e.response.status_code == 429:  # Too Many Requests
#                 logger.warning(f"Rate limit hit for webhook alert: {str(e)}. Retrying after {backoff_factor ** attempt}s...")
#                 time.sleep(backoff_factor ** attempt)  # Exponential backoff
#                 attempt += 1
#             else:
#                 logger.error(f"Failed to send webhook alert: {str(e)}")
#                 return False
#         except Exception as e:
#             logger.error(f"Failed to send webhook alert: {str(e)}")
#             return False
#     logger.error(f"Failed to send webhook alert after {max_retries} retries: {threat_description}")
#     return False