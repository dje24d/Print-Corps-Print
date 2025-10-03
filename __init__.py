from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os
import secrets
import string
from datetime import datetime

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///print_management.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# Models (moved here for simplicity)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='Pending')
    file_name = db.Column(db.String(200))
    original_filename = db.Column(db.String(200))
    pages = db.Column(db.Integer)
    price = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def create_initial_admin(app):
    if not User.query.filter_by(is_superadmin=True).first():
        username = 'admin'
        password = 'admin12345678'
        
        admin = User(
            username=username,
            is_admin=True,
            is_superadmin=True
        )
        from werkzeug.security import generate_password_hash
        admin.password_hash = generate_password_hash(password)
        db.session.add(admin)
        db.session.commit()
        app.logger.info(f"Initial superadmin created: {username}")

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions (remove migrate)
    db.init_app(app)
    # migrate.init_app(app, db)  # Remove this line
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    # Create upload folder
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Register routes directly (instead of blueprints)
    register_routes(app)
    
    # Create initial admin
    with app.app_context():
        db.create_all()
        create_initial_admin(app)
    
    return app

def register_routes(app):
    from flask import render_template, request, redirect, url_for, flash, jsonify
    from flask_login import login_user, logout_user, current_user, login_required
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
    import os
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Main routes
    @app.route('/')
    def home():
        return render_template('index.html')
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        if current_user.is_superadmin:
            return redirect(url_for('superadmin_dashboard'))
        elif current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return render_template('dashboard.html')
    
    # Auth routes
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'danger')
        
        return render_template('login.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('home'))
    
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return redirect(url_for('signup'))
                
            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'danger')
                return redirect(url_for('signup'))
            
            new_user = User(username=username)
            new_user.password_hash = generate_password_hash(password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('signup.html')
    
    # Admin routes
    @app.route('/admin/dashboard')
    @login_required
    def admin_dashboard():
        if not (current_user.is_admin or current_user.is_superadmin):
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard'))
        
        if current_user.is_superadmin:
            return render_template('superadmin_dashboard.html')
        else:
            return render_template('admin_dashboard.html')
    
    @app.route('/superadmin/dashboard')
    @login_required
    def superadmin_dashboard():
        if not current_user.is_superadmin:
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard'))
        return render_template('superadmin_dashboard.html')
    
    # Orders routes
    @app.route('/orders')
    @login_required
    def orders():
        if current_user.is_admin or current_user.is_superadmin:
            orders = Order.query.all()
        else:
            orders = Order.query.filter_by(user_id=current_user.id).all()
        
        return render_template('orders.html', orders=orders)
    
    @app.route('/upload', methods=['GET', 'POST'])
    @login_required
    def upload_file():
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(request.url)
            
            file = request.files['file']
            
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(request.url)
            
            # Simple file validation
            allowed_extensions = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
            if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                flash('Invalid file type', 'danger')
                return redirect(request.url)
            
            try:
                filename = secure_filename(f"user_{current_user.id}_{datetime.now().timestamp()}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Create order
                new_order = Order(
                    user_id=current_user.id,
                    file_name=filename,
                    original_filename=file.filename,
                    pages=1,  # Default page count
                    price=1000,  # Default price
                    status='Pending'
                )
                db.session.add(new_order)
                db.session.commit()
                
                flash('File uploaded successfully!', 'success')
                return redirect(url_for('orders'))
                
            except Exception as e:
                flash('Error uploading file', 'danger')
                app.logger.error(f"File upload error: {str(e)}")
                return redirect(request.url)
        
        return render_template('upload.html')
    
    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('403.html'), 403
    
    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return render_template('500.html'), 500
