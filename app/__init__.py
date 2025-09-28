from flask import Flask
from .config import Config
from .extensions import db, login_manager, migrate

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    # Register blueprints
    from app.auth.routes import auth_bp
    from app.orders.routes import orders_bp
    from app.admin.routes import admin_bp
    from app.payments.routes import payments_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(orders_bp, url_prefix='/orders')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(payments_bp, url_prefix='/payments')
    
    # Create initial admin
    with app.app_context():
        db.create_all()
        from .utils.admin import create_initial_admin
        create_initial_admin(app)
    
    return app