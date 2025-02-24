from flask_restful import Api, Resource
from api.osint_handler import OSINTLookup

api = Api()

class Home(Resource):
    def get(self):
        return {"message": "Welcome to ShopSmart Solutions API!"}, 200

class HealthCheck(Resource):
    def get(self):
        return {"status": "OK"}, 200

api.add_resource(Home, "/")  # Add this line
api.add_resource(HealthCheck, "/health")
api.add_resource(OSINTLookup, "/osint")
