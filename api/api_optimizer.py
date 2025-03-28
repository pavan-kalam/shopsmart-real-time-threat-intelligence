# api/api_optimizer.py
import redis
import json
import logging
from api.fetch_osint import fetch_osint_data
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_optimizer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('api_optimizer')

cache = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

# Modified to log cache misses explicitly
def get_threat_data(query):
    cache_key = f"threat:{query}"
    try:
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Cache hit for query: {query}")
            return json.loads(cached_data)
        else:
            logger.info(f"Cache miss for query: {query}")  # Added for debugging
    except Exception as e:
        logger.error(f"Cache retrieval error: {e}")

    data = fetch_osint_data(query)
    try:
        cache.setex(cache_key, 3600, json.dumps(data, default=serialize_datetime))
        logger.info(f"Cache set for query: {query}")
    except Exception as e:
        logger.error(f"Cache set error: {e}")
    return data

if __name__ == "__main__":
    result = get_threat_data("localhost:5002")
    print(f"Threat Data: {result}")