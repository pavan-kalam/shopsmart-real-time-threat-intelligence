#!/usr/bin/env python3
# api/blue_team_defence.py
import os
import subprocess
import logging
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError
from api.models import db, ThreatData, AlertLog
from api.fetch_osint import get_db_session
from src.api.custom_logging import setup_logger

# Configure logging
logger = setup_logger('blue_team_defence')

# Firewall configuration
IPTABLES = "/sbin/iptables"  # Path to iptables executable
BLOCKED_IPS_LOG = "logs/blocked_ips.log"
BLOCK_DURATION = 24  # Hours to block IPs

def configure_firewall(ip_address, action="block"):
    """Apply or remove firewall rules to block/unblock an IP address."""
    try:
        if not os.path.exists(IPTABLES):
            logger.error("iptables not found. Ensure it is installed.")
            return False

        if action == "block":
            command = [IPTABLES, "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            logger.info(f"Blocking IP: {ip_address}")
        else:
            command = [IPTABLES, "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            logger.info(f"Unblocking IP: {ip_address}")

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            with open(BLOCKED_IPS_LOG, "a") as f:
                f.write(f"{datetime.utcnow()}: {action} IP {ip_address}\n")
            return True
        else:
            logger.error(f"Failed to {action} IP {ip_address}: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error configuring firewall for IP {ip_address}: {str(e)}")
        return False

def auto_block_high_risk_ips():
    """Automatically block IPs associated with high-risk threats."""
    session = get_db_session()
    if not session:
        logger.error("Failed to get database session.")
        return

    try:
        # Fetch high-risk threats from the past 24 hours
        high_risk_threats = session.query(ThreatData).filter(
            ThreatData.risk_score >= 80,
            ThreatData.created_at >= datetime.utcnow() - timedelta(hours=24),
            ThreatData.threat_type.ilike("%IP%")
        ).all()

        blocked_ips = set()
        for threat in high_risk_threats:
            # Extract IP from description (assuming format includes IP)
            ip_match = extract_ip(threat.description)
            if ip_match and ip_match not in blocked_ips:
                if configure_firewall(ip_match, "block"):
                    blocked_ips.add(ip_match)
                    # Log the action in AlertLog
                    alert = AlertLog(
                        threat=threat.description,
                        alert_type="IP Blocked",
                        risk_score=threat.risk_score,
                        threat_type=threat.threat_type,
                        created_at=datetime.utcnow()
                    )
                    session.add(alert)
                    logger.info(f"Blocked IP {ip_match} for threat: {threat.description}")

        session.commit()
        logger.info(f"Processed {len(blocked_ips)} high-risk IPs for blocking.")
    except SQLAlchemyError as e:
        logger.error(f"Database error during IP blocking: {str(e)}")
        session.rollback()
    except Exception as e:
        logger.error(f"Error in auto_block_high_risk_ips: {str(e)}")
    finally:
        session.close()

def extract_ip(description):
    """Extract IP address from threat description."""
    import re
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(ip_pattern, description)
    return match.group(0) if match else None

def cleanup_old_blocks():
    """Unblock IPs after the block duration expires."""
    session = get_db_session()
    if not session:
        logger.error("Failed to get database session for cleanup.")
        return

    try:
        expired_blocks = session.query(AlertLog).filter(
            AlertLog.alert_type == "IP Blocked",
            AlertLog.created_at < datetime.utcnow() - timedelta(hours=BLOCK_DURATION)
        ).all()

        for block in expired_blocks:
            ip = extract_ip(block.threat)
            if ip and configure_firewall(ip, "unblock"):
                session.delete(block)
                logger.info(f"Removed expired block for IP: {ip}")

        session.commit()
    except SQLAlchemyError as e:
        logger.error(f"Database error during cleanup: {str(e)}")
        session.rollback()
    except Exception as e:
        logger.error(f"Error in cleanup_old_blocks: {str(e)}")
    finally:
        session.close()

if __name__ == "__main__":
    # Test the functionality
    auto_block_high_risk_ips()
    cleanup_old_blocks()