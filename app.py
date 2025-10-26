from flask import Flask
from config import Config
from routes.analyze_routes import analyze_bp
from utils.logger import setup_logger

logger = setup_logger()

def createApp():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.register_blueprint(analyze_bp)
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8080, debug=app.config["DEBUG"])
