import time
import schedule
from datetime import datetime
from your_module import fetch_and_store_osint_data  # Import the function from your module

# Function to run the OSINT data fetch task
def fetch_osint_data_job():
    print(f"[{datetime.now()}] Starting OSINT data fetch job...")
    try:
        fetch_and_store_osint_data()  # Call the function to fetch and store OSINT data
        print(f"[{datetime.now()}] OSINT data fetch job completed successfully.")
    except Exception as e:
        print(f"[{datetime.now()}] Error in OSINT data fetch job: {e}")

# Schedule the job to run every 6 hours
schedule.every(6).hours.do(fetch_osint_data_job)

# Main loop to keep the scheduler running
if __name__ == "__main__":
    print(f"[{datetime.now()}] OSINT threat data scheduler started. Fetching data every 6 hours...")
    while True:
        schedule.run_pending()  # Run pending scheduled tasks
        time.sleep(1)  # Sleep for 1 second to avoid high CPU usage