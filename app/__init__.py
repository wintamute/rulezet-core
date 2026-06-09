from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_session import Session
from sqlalchemy.orm import sessionmaker
from config import config as Config
import os
from flask_mail import Mail, Message

load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()
login_manager = LoginManager()
sess = Session()
ThreadLocalSession = None
mail = Mail()

def create_app():
    load_dotenv()

    app = Flask(__name__)
    global ThreadLocalSession
    
    config_name = os.environ.get("FLASKENV")

    app.config.from_object(Config[config_name])

    Config[config_name].init_app(app)

    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login_manager.login_view = "account.login"
    login_manager.init_app(app)
    app.config["SESSION_SQLALCHEMY"] = db
    sess.init_app(app)

    mail.init_app(app)

    from .home import home_blueprint

    from .features.account.account import account_blueprint
    from .features.rule.rule import rule_blueprint  
    from .features.bundle.bundle import bundle_blueprint
    from .features.tags.tags import tags_blueprint
    from app.features.jobs.jobs import jobs_blueprint
    from app.features.connector.connector import connector_blueprint

    app.register_blueprint(home_blueprint, url_prefix="/")
    app.register_blueprint(account_blueprint, url_prefix="/account")
    app.register_blueprint(rule_blueprint, url_prefix="/rule")
    app.register_blueprint(bundle_blueprint, url_prefix="/bundle")
    app.register_blueprint(tags_blueprint, url_prefix="/tags")
    app.register_blueprint(jobs_blueprint, url_prefix='/jobs')
    app.register_blueprint(connector_blueprint, url_prefix='/connector')

    from app.api.api import api_blueprint

    csrf.exempt(api_blueprint)
   
    app.register_blueprint(api_blueprint, url_prefix="/api")


    from app.features.jobs import job_handlers  # noqa
    from app.features.jobs.job_worker import start_worker
    start_worker(app)

    with app.app_context():
        try:
            from app.features.connector.connector_core import seed_official_connector
            seed_official_connector()
        except Exception:
            pass

    _version_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'version')
    try:
        with open(_version_path) as _f:
            _app_version = _f.read().strip()
    except OSError:
        _app_version = 'unknown'

    @app.context_processor
    def inject_version():
        return {'app_version': _app_version}

    return app
    
    