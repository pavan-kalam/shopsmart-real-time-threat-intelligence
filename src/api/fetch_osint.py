import requests
import psycopg2
import schedule
import time
from api.virustotal import fetch_virustotal_data
from api.hibp import check_email_breach
from api.abuseipdb import check_ip_abuse
from api.shodan import search_shodan # type: ignore

# Database Connection Configuration
db_config = {
    "dbname": "threat_intel",
    "user": "admin",
    "password": "securepass",
    "host": "localhost",
    "port": "5432"
}

# Function to fetch threat data from Shodan
def fetch_shodan(ip="8.8.8.8"):
    return search_shodan("port:22", "your_shodan_api_key")

# Function to fetch threat data from Have I Been Pwned
def fetch_hibp(email="test@example.com"):
    return check_email_breach(email)

# Function to fetch threat data from VirusTotal
def fetch_virustotal(url="http://example.com"):
    return fetch_virustotal_data("your_virustotal_api_key", url)

# Function to fetch threat data from AbuseIPDB
def fetch_abuseipdb(ip_address="8.8.8.8"):
    return check_ip_abuse("your_abuseipdb_api_key", ip_address)

# Function to store threat data in the database
def store_threat_data(asset_id, threat_name, vulnerability_description, likelihood, impact):
    try:
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tva_mapping (asset_id, threat_name, vulnerability_description, likelihood, impact, risk_score)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (asset_id, threat_name, vulnerability_description, likelihood, impact, likelihood * impact))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Stored threat: {threat_name}")
    except Exception as e:
        print(f"Error storing threat data: {e}")

# Automated task to fetch and store OSINT threat data
def fetch_and_store_osint():
    shodan_data = fetch_shodan()
    hibp_data = fetch_hibp()
    virustotal_data = fetch_virustotal()
    abuseipdb_data = fetch_abuseipdb()
    
    store_threat_data(1, "Exposed Ports", shodan_data, 4, 5)
    store_threat_data(2, "Credential Breach", hibp_data, 5, 5)
    store_threat_data(3, "Malware Analysis", virustotal_data, 4, 4)
    store_threat_data(4, "Suspicious IP Activity", abuseipdb_data, 3, 4)

# Schedule the script to run periodically
schedule.every(6).hours.do(fetch_and_store_osint)  # Runs every 6 hours

if __name__ == "__main__":
    fetch_and_store_osint()  # Run once immediately
    while True:
        schedule.run_pending()
        time.sleep(3600)  # Check every hour
