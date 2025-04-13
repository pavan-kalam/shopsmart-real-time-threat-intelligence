#!/usr/bin/env python3
# api/ai_threat_hunting.py
import os
import logging
from datetime import datetime, timedelta
from transformers import pipeline
from sqlalchemy.exc import SQLAlchemyError
from api.models import db, ThreatData, AlertLog
from api.fetch_osint import get_db_session
from src.api.custom_logging import setup_logger

# Configure logging
logger = setup_logger('ai_threat_hunting')

# Initialize Hugging Face model
try:
    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    logger.info("Initialized Hugging Face zero-shot classifier for threat hunting")
except Exception as e:
    logger.error(f"Failed to initialize classifier: {str(e)}")
    classifier = None

def analyze_behavior_patterns():
    """Analyze recent threat data for anomalous behavior using LLM."""
    if not classifier:
        logger.error("Classifier not initialized. Skipping anomaly detection.")
        return

    session = get_db_session()
    if not session:
        logger.error("Failed to get database session.")
        return

    try:
        # Fetch recent threats (last 48 hours)
        recent_threats = session.query(ThreatData).filter(
            ThreatData.created_at >= datetime.utcnow() - timedelta(hours=48)
        ).all()

        if not recent_threats:
            logger.info("No recent threats to analyze.")
            return

        # Define labels for anomaly detection
        labels = ["Normal", "Suspicious", "Malicious"]

        for threat in recent_threats:
            # Prepare text for classification
            text = f"Threat Type: {threat.threat_type}, Description: {threat.description}, Risk Score: {threat.risk_score}"
            
            # Classify behavior
            result = classifier(text, candidate_labels=labels, multi_label=False)
            top_label = result["labels"][0]
            confidence = result["scores"][0]

            if top_label in ["Suspicious", "Malicious"] and confidence > 0.7:
                # Log anomaly as an alert
                alert = AlertLog(
                    threat=threat.description,
                    alert_type=f"AI-Detected {top_label}",
                    risk_score=int(threat.risk_score * (1 + confidence)),
                    threat_type=threat.threat_type,
                    created_at=datetime.utcnow()
                )
                session.add(alert)
                logger.info(
                    f"Detected {top_label} behavior for threat: {threat.description}, "
                    f"Confidence: {confidence:.2f}, New Risk Score: {alert.risk_score}"
                )

        session.commit()
        logger.info(f"Processed {len(recent_threats)} threats for anomaly detection.")
    except SQLAlchemyError as e:
        logger.error(f"Database error during anomaly detection: {str(e)}")
        session.rollback()
    except Exception as e:
        logger.error(f"Error in analyze_behavior_patterns: {str(e)}")
    finally:
        session.close()

def proactive_threat_hunt(query="localhost:5002"):
    """Proactively fetch and analyze OSINT data for anomalies."""
    from api.api_optimizer import get_threat_data
    try:
        # Fetch fresh OSINT data
        osint_data = get_threat_data(query)
        if not osint_data or "events" not in osint_data:
            logger.warning(f"No valid OSINT data for query: {query}")
            return

        # Save new threats to database
        from api.fetch_osint import save_threat_data, process_threat_data
        processed_threats = process_threat_data(osint_data["events"])
        save_threat_data(processed_threats)

        # Analyze for anomalies
        analyze_behavior_patterns()
        logger.info(f"Completed proactive threat hunt for query: {query}")
    except Exception as e:
        logger.error(f"Error in proactive_threat_hunt: {str(e)}")

if __name__ == "__main__":
    # Test the functionality
    proactive_threat_hunt()