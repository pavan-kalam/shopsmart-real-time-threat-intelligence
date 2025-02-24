from flask import Flask
from flask_cors import CORS
from api.routes import api

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config.from_object("config")

    api.init_app(app)

    return app
