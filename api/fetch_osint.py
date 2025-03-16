import requests
import psycopg2
import time
from datetime import datetime

# API Keys (Replace with your actual API keys)
SHODAN_API_KEY = "dfhwfkMbOVzPFxUJvxa8Yn6qMCxOvqBD"
HIBP_API_KEY = "your_hibp_api_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_api_key"

# Database connection details
DB_CONFIG = {
    "dbname": "shopsmart",
    "user": "shopsmart",
    "password": "123456789",
    "host": "localhost",
    "port": "5432"
}

# Shodan API to fetch IP information
def fetch_shodan_data(ip_address):
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Shodan data: {e}")
        return None

# HIBP API to check email breaches
def fetch_hibp_data(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "YourAppName/1.0"  # Replace with your app name
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching HIBP data: {e}")
        return None

# SecurityTrails API to fetch domain information
def fetch_securitytrails_data(domain):
    url = f"https://api.securitytrails.com/v1/domain/{domain}"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching SecurityTrails data: {e}")
        return None

# Store threat data in the database
def store_threat_data(threat_type, source_name, source_url, description, severity_level, confidence_level, affected_assets, mitigation_recommendations, tags):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_data (
                threat_type, source_name, source_url, description, severity_level, confidence_level,
                first_seen, last_updated, affected_assets, mitigation_recommendations, tags, is_active
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            threat_type, source_name, source_url, description, severity_level, confidence_level,
            datetime.now(), datetime.now(), affected_assets, mitigation_recommendations, tags, True
        ))
        conn.commit()
        print("Threat data stored successfully!")
    except psycopg2.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

# Fetch and store OSINT data
def fetch_and_store_osint_data():
    # Example IP, email, and domain to fetch data for
    ip_address = "8.8.8.8"
    email = "test@example.com"
    domain = "example.com"

    # Fetch Shodan data
    shodan_data = fetch_shodan_data(ip_address)
    if shodan_data:
        store_threat_data(
            threat_type="Open Ports Detected",
            source_name="Shodan",
            source_url=f"https://www.shodan.io/host/{ip_address}",
            description=f"Open ports: {shodan_data.get('ports', [])}",
            severity_level="High",
            confidence_level="Medium",
            affected_assets=ip_address,
            mitigation_recommendations="Close unnecessary ports and secure services.",
            tags=["open_ports", "network_security"]
        )

    # Fetch HIBP data
    hibp_data = fetch_hibp_data(email)
    if hibp_data:
        for breach in hibp_data:
            store_threat_data(
                threat_type="Email Breach Detected",
                source_name="Have I Been Pwned",
                source_url=f"https://haveibeenpwned.com/breach/{breach.get('Name')}",
                description=f"Email {email} was found in the {breach.get('Name')} breach.",
                severity_level="Medium",
                confidence_level="High",
                affected_assets=email,
                mitigation_recommendations="Change your password and enable 2FA.",
                tags=["email_breach", "account_security"]
            )

    # Fetch SecurityTrails data
    securitytrails_data = fetch_securitytrails_data(domain)
    if securitytrails_data:
        store_threat_data(
            threat_type="Domain Information Exposed",
            source_name="SecurityTrails",
            source_url=f"https://securitytrails.com/domain/{domain}",
            description=f"Domain {domain} is associated with IP {securitytrails_data.get('current_ip', 'N/A')}.",
            severity_level="Low",
            confidence_level="High",
            affected_assets=domain,
            mitigation_recommendations="Monitor domain activity and secure DNS records.",
            tags=["domain_info", "dns_security"]
        )

# Run the script periodically
def run_periodically(interval=3600):  # Default interval: 1 hour (3600 seconds)
    while True:
        fetch_and_store_osint_data()
        time.sleep(interval)

if __name__ == "__main__":
    fetch_and_store_osint_data()  # Run once
    # Uncomment the following line to run periodically
    # run_periodically()