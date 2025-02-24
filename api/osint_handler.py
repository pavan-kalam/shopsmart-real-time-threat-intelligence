from flask import request
from flask_restful import Resource
import requests

class OSINTLookup(Resource):
    def get(self):
        query = request.args.get("query")
        if not query:
            return {"error": "Query parameter required"}, 400

        # Example OSINT API call (replace with actual service)
        response = requests.get(f"https://some-osint-api.com/search?query={query}")

        return response.json(), response.status_code
