import requests
import psycopg2
import time

# API Keys (Replace with your actual API keys)
SHODAN_API_KEY = "your_shodan_api_key"
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
        "User-Agent": "YourAppName/1.0"
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
def store_threat_data(asset_id, threat_name, vulnerability_description, likelihood, impact):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tva_mapping (asset_id, threat_name, vulnerability_description, likelihood, impact)
            VALUES (%s, %s, %s, %s, %s)
        """, (asset_id, threat_name, vulnerability_description, likelihood, impact))
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
            asset_id=1,  # Replace with actual asset ID
            threat_name="Open Ports Detected",
            vulnerability_description=f"Open ports: {shodan_data.get('ports', [])}",
            likelihood=4,
            impact=5
        )

    # Fetch HIBP data
    hibp_data = fetch_hibp_data(email)
    if hibp_data:
        for breach in hibp_data:
            store_threat_data(
                asset_id=2,  # Replace with actual asset ID
                threat_name="Email Breach Detected",
                vulnerability_description=f"Breach: {breach.get('Name')}",
                likelihood=3,
                impact=4
            )

    # Fetch SecurityTrails data
    securitytrails_data = fetch_securitytrails_data(domain)
    if securitytrails_data:
        store_threat_data(
            asset_id=3,  # Replace with actual asset ID
            threat_name="Domain Information Exposed",
            vulnerability_description=f"Domain: {securitytrails_data.get('current_ip', 'N/A')}",
            likelihood=2,
            impact=3
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