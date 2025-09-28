import os
import secrets
import string
import math
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory, current_app, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, case, or_, event
from sqlalchemy.engine import Engine
from document_utils import count_pages, get_file_type
import geopy.distance
from geopy.geocoders import Nominatim
from geoalchemy2 import Geometry
from sqlalchemy.orm import deferred

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Add this function to enable spatialite for SQLite
def enable_spatialite(dbapi_conn, connection_record):
    dbapi_conn.enable_load_extension(True)
    try:
        # Try loading mod_spatialite first (newer versions)
        dbapi_conn.execute('SELECT load_extension("mod_spatialite")')
    except:
        try:
            # Fall back to libspatialite
            dbapi_conn.execute('SELECT load_extension("libspatialite")')
        except:
            # Final fallback - try without extension name
            try:
                dbapi_conn.execute('SELECT load_extension("mod_spatialite.so")')
            except:
                try:
                    dbapi_conn.execute('SELECT load_extension("libspatialite.so")')
                except:
                    print("Warning: Could not load spatialite extension")
    dbapi_conn.enable_load_extension(False)

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    
    # Database settings - use SQLite with spatialite
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///print_management.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    
    # Payment settings
    MTN_MERCHANT_CODE = os.environ.get('MTN_MERCHANT_CODE', 'YOUR_MTN_CODE')
    AIRTEL_MERCHANT_ID = os.environ.get('AIRTEL_MERCHANT_ID', 'YOUR_AIRTEL_ID')
    
    # Business settings
    MINIMUM_DEPOSIT = 1000  # UGX
    CURRENCY = 'UGX'
    
    # File uploads
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Admin settings
    INITIAL_ADMIN_USERNAME = os.environ.get('INITIAL_ADMIN_USERNAME', 'superadmin')
    INITIAL_ADMIN_PASSWORD = os.environ.get('INITIAL_ADMIN_PASSWORD', 'superadmin12345678')
    
    # Location settings
    MAX_ASSIGNMENT_DISTANCE_KM = 10  # Maximum distance for admin assignment

# Custom currency formatting function
def format_currency(amount):
    if amount is None:
        return "UGX 0"
    try:
        return f"UGX {float(amount):,.0f}".replace(",", " ")
    except (ValueError, TypeError):
        return "UGX 0"

# Location utility functions
def get_coordinates_from_address(address):
    """Convert address to latitude/longitude coordinates"""
    try:
        geolocator = Nominatim(user_agent="print_management_system")
        location = geolocator.geocode(address)
        if location:
            return location.latitude, location.longitude
        return None, None
    except Exception as e:
        current_app.logger.error(f"Geocoding error: {str(e)}")
        return None, None

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two points in kilometers using Haversine formula"""
    if None in (lat1, lon1, lat2, lon2):
        return float('inf')
    
    # Haversine formula
    R = 6371  # Earth's radius in kilometers
    
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    distance = R * c
    return distance

def find_nearest_admins(user_lat, user_lon, max_distance_km=10):
    """Find admins within specified distance using manual calculation"""
    if user_lat is None or user_lon is None:
        return []
    
    admins = User.query.filter_by(is_admin=True).all()
    nearby_admins = []
    
    for admin in admins:
        if hasattr(admin, 'location') and admin.location:
            distance = calculate_distance(
                user_lat, user_lon,
                admin.location.latitude, admin.location.longitude
            )
            if distance <= max_distance_km:
                nearby_admins.append({
                    'admin': admin,
                    'distance': distance
                })
    
    # Sort by distance
    nearby_admins.sort(key=lambda x: x['distance'])
    return nearby_admins

# Models
class UserLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    address = db.Column(db.String(200))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    # Remove the Geometry column for SQLite compatibility
    # location = deferred(db.Column(Geometry(geometry_type='POINT')))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('location', uselist=False))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    full_name = db.Column(db.String(150), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    is_one_time_password = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    location_set = db.Column(db.Boolean, default=False)  # Track if location is set
    
    # Relationships
    orders = db.relationship('Order', backref='customer', foreign_keys='Order.user_id', lazy=True)
    assigned_orders = db.relationship('Order', backref='assigned_admin', foreign_keys='Order.assigned_admin_id', lazy=True)

    def __init__(self, **kwargs):
        if 'email' in kwargs and kwargs['email'] == '':
            kwargs['email'] = None
        super().__init__(**kwargs)

    def set_password(self, password, is_one_time=False):
        if (self.is_admin or self.is_superadmin) and len(password) < 12:
            raise ValueError("Admin passwords must be at least 12 characters")
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.is_one_time_password = is_one_time

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def verify_password(self, password):
        if self.is_admin or self.is_superadmin:
            if len(password) < 12:
                raise ValueError("Admin passwords require 12+ characters")
        return check_password_hash(self.password_hash, password)
    
    def generate_reset_token(self, expires_hours=24):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=expires_hours)
        return self.reset_token
    
    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expires = None
    
    def set_location(self, address, latitude, longitude):
        """Set or update user location"""
        if not self.location:
            self.location = UserLocation()
        
        self.location.address = address
        self.location.latitude = latitude
        self.location.longitude = longitude
        # Remove spatial reference for SQLite compatibility
        # self.location.location = f"POINT({longitude} {latitude})"
        self.location_set = True
        
    def get_distance_to(self, other_lat, other_lon):
        """Get distance to another point in km"""
        if not self.location or not self.location.latitude or not self.location.longitude:
            return float('inf')
        return calculate_distance(self.location.latitude, self.location.longitude, other_lat, other_lon)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    processed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='Pending')
    processing_started_at = db.Column(db.DateTime, nullable=True)
    processing_completed_at = db.Column(db.DateTime, nullable=True)
    file_name = db.Column(db.String(200))
    original_filename = db.Column(db.String(200))
    pages = db.Column(db.Integer)
    color = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    cancelled_at = db.Column(db.DateTime, nullable=True)
    cancellation_reason = db.Column(db.Text, nullable=True)
    is_rush = db.Column(db.Boolean, default=False)
    priority_level = db.Column(db.String(20), default='Normal')
    price = db.Column(db.Float)
    user_notes = db.Column(db.Text, nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)
    paper_type = db.Column(db.String(50))
    paper_size = db.Column(db.String(20))
    copies = db.Column(db.Integer, default=1)
    is_template = db.Column(db.Boolean, default=False)
    template_name = db.Column(db.String(100), nullable=True)
    payment_method = db.Column(db.String(20), nullable=False, default='Mobile Money')
    payment_status = db.Column(db.String(20), default='Pending')
    transaction_id = db.Column(db.String(100))
    mobile_money_provider = db.Column(db.String(20))
    mobile_money_number = db.Column(db.String(15))
    auto_page_count = db.Column(db.Boolean, default=False)
    delivery_address = db.Column(db.Text, nullable=True)
    delivery_contact = db.Column(db.String(50), nullable=True)
    # Location fields for order
    delivery_latitude = db.Column(db.Float, nullable=True)
    delivery_longitude = db.Column(db.Float, nullable=True)

    assigned_admin_rel = db.relationship('User', foreign_keys='Order.assigned_admin_id', backref='orders_assigned')
    processed_by_rel = db.relationship('User', foreign_keys='Order.processed_by_id', backref='orders_processed')

class PaymentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    provider = db.Column(db.String(20))
    amount = db.Column(db.Float)
    initiated_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='Pending')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    app.jinja_env.filters['format_currency'] = format_currency

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Add spatialite support for SQLite
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:'):
        @event.listens_for(Engine, "connect")
        def connect(dbapi_conn, connection_record):
            enable_spatialite(dbapi_conn, connection_record)

    register_routes(app)

    with app.app_context():
        db.create_all()
        create_initial_admin(app)
    
    return app

def create_initial_admin(app):
    if not User.query.filter_by(is_superadmin=True).first():
        username = app.config['INITIAL_ADMIN_USERNAME']
        password = app.config['INITIAL_ADMIN_PASSWORD']

        if not password or len(password) < 12:
            alphabet = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(alphabet) for _ in range(16))
            app.logger.warning(
                f"Provided INITIAL_ADMIN_PASSWORD was too short. "
                f"A secure password has been auto-generated for superadmin '{username}': {password}"
            )

        admin = User(
            username=username,
            is_admin=True,
            is_superadmin=True
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        app.logger.info(f"Initial superadmin created: {username}")

def register_routes(app):
    
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

    def calculate_price(pages, copies, paper_type, paper_size, color, priority):
        base_price = 200  # UGX per page
        
        paper_type_multipliers = {
            "Plain Paper": 1.0,
            "Art Paper": 2.5,
            "Art Board": 3.0
        }
        
        paper_size_multipliers = {
            "A3": 5.0,
            "A4": 1.0,
            "A5": 1.25,
            "Other": 1.0
        }
        
        priority_multipliers = {
            'Normal': 1.0,
            'High': 1.5,
            'Rush': 2.0
        }
        
        # Calculate base total
        total = base_price * pages * copies
        
        # Apply multipliers
        total *= paper_type_multipliers.get(paper_type, 1.0)
        total *= paper_size_multipliers.get(paper_size, 1.0)
        
        # Apply color multiplier (2.5x for color, 1x for black/white)
        if isinstance(color, str):
            color = color.lower() == 'true'
        
        color_multiplier = 2.5 if color else 1.0
        total *= color_multiplier
        
        # Apply priority multiplier
        total *= priority_multipliers.get(priority, 1.0)
        
        return total

    def get_order_by_id(order_id):
        return Order.query.get(order_id)

    def update_order(order_id, data):
        order = Order.query.get(order_id)
        if order:
            order.status = data.get('status', order.status)
            order.priority_level = data.get('priority_level', order.priority_level)
            order.admin_notes = data.get('admin_notes', order.admin_notes)
            order.payment_status = data.get('payment_status', order.payment_status)
            order.is_rush = data.get('is_rush', order.is_rush) == 'true' if 'is_rush' in data else order.is_rush
            order.pages = int(data.get('pages', order.pages))
            order.copies = int(data.get('copies', order.copies))
            order.paper_type = data.get('paper_type', order.paper_type)
            order.paper_size = data.get('paper_size', order.paper_size)
            order.color = data.get('color', order.color) == 'true' if 'color' in data else order.color
            
            if 'assigned_admin_id' in data and data['assigned_admin_id']:
                order.assigned_admin_id = int(data['assigned_admin_id'])
            
            if any(key in data for key in ['pages', 'copies', 'paper_type', 'paper_size', 'color', 'priority_level']):
                order.price = calculate_price(
                    order.pages, order.copies, order.paper_type, 
                    order.paper_size, order.color, order.priority_level
                )
            
            db.session.commit()
        return order

    def assign_order_to_nearest_admin(order, delivery_address=None):
        """Assign order to the nearest available admin within range"""
        if delivery_address:
            # Get coordinates from delivery address
            lat, lon = get_coordinates_from_address(delivery_address)
            if lat is not None and lon is not None:
                order.delivery_latitude = lat
                order.delivery_longitude = lon
                
                # Find nearest admins
                nearby_admins = find_nearest_admins(
                    lat, lon, 
                    app.config['MAX_ASSIGNMENT_DISTANCE_KM']
                )
                
                if nearby_admins:
                    # Assign to the nearest admin
                    nearest_admin = nearby_admins[0]['admin']
                    order.assigned_admin_id = nearest_admin.id
                    order.status = 'Processing'
                    order.processing_started_at = datetime.utcnow()
                    db.session.commit()
                    
                    app.logger.info(f"Order {order.id} assigned to admin {nearest_admin.username} "
                                  f"(distance: {nearby_admins[0]['distance']:.2f} km)")
                    return True
        
        # If no nearby admin found or no address provided, leave unassigned
        return False

    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    @app.context_processor
    def utility_processor():
        def is_superadmin():
            return current_user.is_authenticated and current_user.is_superadmin
        
        return dict(is_superadmin=is_superadmin, format_currency=format_currency)

    # User order management routes
    @app.route('/my_orders')
    @login_required
    def my_orders():
        page = request.args.get('page', 1, type=int)
        per_page = 10
        status_filter = request.args.get('status', '')
        
        query = Order.query.filter_by(user_id=current_user.id)
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        orders = query.order_by(Order.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return render_template('my_orders.html', orders=orders, status_filter=status_filter)

    @app.route('/reorder/<int:order_id>')
    @login_required
    def reorder(order_id):
        original_order = Order.query.get_or_404(order_id)
        
        if original_order.user_id != current_user.id:
            abort(403)
        
        # Store order details in session for the complete_order page
        session['reorder_data'] = {
            'pages': original_order.pages,
            'copies': original_order.copies,
            'paper_type': original_order.paper_type,
            'paper_size': original_order.paper_size,
            'color': original_order.color,
            'priority': original_order.priority_level,
            'user_notes': f"Reordered from order #{original_order.id}",
            'delivery_address': original_order.delivery_address
        }
        
        # Copy the file for the new order
        if original_order.file_name and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], original_order.file_name)):
            new_filename = secure_filename(f"reorder_{current_user.id}_{datetime.now().timestamp()}_{original_order.original_filename}")
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], original_order.file_name)
            new_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            
            import shutil
            shutil.copy2(old_path, new_path)
            
            session['uploaded_file'] = {
                'filename': new_filename,
                'original_filename': original_order.original_filename,
                'page_count': original_order.pages
            }
            
            flash('Order ready for reordering. Please review and confirm details.', 'success')
            return redirect(url_for('complete_order'))
        
        flash('Original file not found. Please upload a new file.', 'warning')
        return redirect(url_for('upload_file'))

    @app.route('/download_my_order/<int:order_id>')
    @login_required
    def download_my_order(order_id):
        order = Order.query.get_or_404(order_id)
        
        if order.user_id != current_user.id:
            abort(403)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], order.file_name)
        if not os.path.exists(file_path):
            flash('File not found. It may have been deleted.', 'error')
            return redirect(url_for('my_orders'))
        
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            order.file_name,
            as_attachment=True,
            download_name=order.original_filename
        )








    # Login route (fixed)
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            remember = 'remember' in request.form
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user, remember=remember)
                
                # Check if password change is required (one-time password)
                if user.is_one_time_password:
                    session['require_password_change'] = user.id
                    flash('Please change your one-time password', 'warning')
                    return redirect(url_for('change_password'))
                
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
        
        return render_template('login.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip()
            phone_number = request.form.get('phone_number', '').strip()
            
            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return redirect(url_for('signup'))
                
            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'danger')
                return redirect(url_for('signup'))
            
            # Check if email already exists (if provided)
            if email and User.query.filter_by(email=email).first():
                flash('Email already exists!', 'danger')
                return redirect(url_for('signup'))
            
            new_user = User(
                username=username,
                email=email if email else None,
                full_name=full_name if full_name else None,
                phone_number=phone_number if phone_number else None
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('signup.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('home'))

    # Main application routes
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
        
        # Get recent orders for the user (5 most recent)
        orders = Order.query.filter_by(user_id=current_user.id)\
                            .order_by(Order.created_at.desc())\
                            .limit(5).all()
        
        # Get templates if needed
        templates = Order.query.filter_by(
            user_id=current_user.id,
            is_template=True
        ).order_by(Order.created_at.desc()).limit(5).all()
        
        # Get order statistics
        status_counts = {
            'total': Order.query.filter_by(user_id=current_user.id).count(),
            'pending': Order.query.filter_by(user_id=current_user.id, status='Pending').count(),
            'processing': Order.query.filter_by(user_id=current_user.id, status='Processing').count(),
            'completed': Order.query.filter_by(user_id=current_user.id, status='Completed').count(),
            'cancelled': Order.query.filter_by(user_id=current_user.id, status='Cancelled').count()
        }
        
        return render_template('dashboard.html', 
                            orders=orders,
                            status_counts=status_counts,
                            templates=templates)

    @app.route('/upload_file', methods=['GET', 'POST'])
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
            
            if not allowed_file(file.filename):
                flash('Invalid file type. Allowed formats: PDF, DOC, DOCX, JPG, PNG', 'danger')
                return redirect(request.url)
            
            try:
                # Save file temporarily
                filename = secure_filename(f"temp_{current_user.id}_{datetime.now().timestamp()}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Count pages automatically
                file_content = None
                with open(filepath, 'rb') as f:
                    file_content = f.read()
                
                auto_page_count = count_pages(filepath, file_content)
                
                if auto_page_count is None:
                    flash('Could not automatically detect page count. Please enter it manually.', 'warning')
                    auto_page_count = 1
                
                # Store file info in session
                session['uploaded_file'] = {
                    'filename': filename,
                    'original_filename': file.filename,
                    'page_count': auto_page_count
                }
                
                return redirect(url_for('complete_order'))
                
            except Exception as e:
                flash('Error processing your file. Please try again.', 'danger')
                app.logger.error(f"File upload error: {str(e)}")
                return redirect(request.url)
        
        return render_template('upload_file.html')

    @app.route('/complete_order', methods=['GET', 'POST'])
    @login_required
    def complete_order():
        if 'uploaded_file' not in session:
            flash('Please upload a file first', 'warning')
            return redirect(url_for('upload_file'))
        
        file_info = session['uploaded_file']
        
        # Check if we have reorder data
        reorder_data = session.get('reorder_data', {})
        
        # Calculate initial estimated price using reorder data if available
        pages = reorder_data.get('pages', file_info['page_count'])
        copies = reorder_data.get('copies', 1)
        paper_type = reorder_data.get('paper_type', 'Plain Paper')
        paper_size = reorder_data.get('paper_size', 'A4')
        color = reorder_data.get('color', False)
        priority = reorder_data.get('priority', 'Normal')
        delivery_address = reorder_data.get('delivery_address', '')
        
        initial_estimated_price = calculate_price(
            pages, copies, paper_type, paper_size, color, priority
        )
        
        if request.method == 'POST':
            try:
                # Process order details
                pages = int(request.form['pages'])
                copies = int(request.form.get('copies', 1))
                paper_type = request.form['paper_type']
                paper_size = request.form['paper_size']
                priority = request.form['priority']
                color = request.form.get('color') == 'true'
                payment_method = request.form.get('payment_method', 'Mobile Money')
                delivery_address = request.form.get('delivery_address', '')
                delivery_contact = request.form.get('delivery_contact', '')
                
                # Validate inputs
                if pages < 1 or pages > 500:
                    raise ValueError("Invalid page count (1-500)")
                if copies < 1 or copies > 100:
                    raise ValueError("Invalid copies count (1-100)")
                
                # Calculate price
                total_price = calculate_price(
                    pages, copies, paper_type, paper_size, color, priority
                )
                
                # Rename the temporary file
                permanent_filename = secure_filename(f"user_{current_user.id}_{datetime.now().timestamp()}_{file_info['original_filename']}")
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
                new_path = os.path.join(app.config['UPLOAD_FOLDER'], permanent_filename)
                os.rename(old_path, new_path)
                
                # Create order
                new_order = Order(
                    user_id=current_user.id,
                    file_name=permanent_filename,
                    original_filename=file_info['original_filename'],
                    pages=pages,
                    copies=copies,
                    paper_type=paper_type,
                    paper_size=paper_size,
                    color=color,
                    is_rush=(priority == 'Rush'),
                    priority_level=priority,
                    price=total_price,
                    status='Pending',
                    user_notes=request.form.get('user_notes', '').strip(),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    payment_method=payment_method,
                    payment_status='Pending' if payment_method != 'Pay on Delivery' else 'Awaiting Collection',
                    auto_page_count=True,
                    delivery_address=delivery_address,
                    delivery_contact=delivery_contact
                )
                
                # Process payment
                if payment_method == 'Mobile Money':
                    transaction_id = f"MOMO-{datetime.now().timestamp()}"
                    new_order.transaction_id = transaction_id
                    new_order.mobile_money_provider = request.form.get('mobile_provider')
                    new_order.mobile_money_number = request.form.get('mobile_number')
                elif payment_method == 'Pay on Delivery':
                    new_order.delivery_address = delivery_address
                    new_order.delivery_contact = delivery_contact
                
                db.session.add(new_order)
                db.session.commit()
                
                # Try to assign to nearest admin if delivery address is provided
                if delivery_address:
                    assign_order_to_nearest_admin(new_order, delivery_address)
                
                # Clean up session
                session.pop('uploaded_file', None)
                session.pop('reorder_data', None)
                
                flash(f'Order #{new_order.id} submitted! Total: UGX {total_price:,.0f}'.replace(",", " "), 'success')
                
                if payment_method == 'Mobile Money':
                    return redirect(url_for('initiate_payment', order_id=new_order.id))
                
                return redirect(url_for('dashboard'))
                
            except ValueError as ve:
                flash(f'Invalid input: {str(ve)}', 'danger')
                return redirect(request.url)
            except Exception as e:
                flash('Error processing your order. Please try again.', 'danger')
                app.logger.error(f"Order completion error: {str(e)}")
                return redirect(request.url)
        
        return render_template('complete_order.html', 
                            file_info=file_info,
                            reorder_data=reorder_data,
                            estimated_price=initial_estimated_price)

    @app.route('/submit_order', methods=['GET'])
    @login_required
    def submit_order():
        # Redirect to the new upload flow for backward compatibility
        return redirect(url_for('upload_file'))

    @app.route('/initiate_payment/<int:order_id>')
    @login_required
    def initiate_payment(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id:
            abort(403)
        
        if order.payment_method == 'Mobile Money':
            amount = str(int(order.price))
            merchant_code = current_app.config['MTN_MERCHANT_CODE']
            
            mtn_link = f"*165*3*{merchant_code}*{amount}*{order.id}%23"
            airtel_link = f"*185*{merchant_code}*{amount}%23"
            
            return render_template('payment_initiate.html',
                                order=order,
                                mtn_link=mtn_link,
                                airtel_link=airtel_link,
                                amount=amount)
        
        flash('Payment method not supported', 'danger')
        return redirect(url_for('dashboard'))

    # Admin routes
    @app.route('/admin/dashboard')
    @login_required
    def admin_dashboard():
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
        
        # Redirect super admins to the super admin dashboard
        if current_user.is_superadmin:
            return redirect(url_for('superadmin_dashboard'))
        
        # Regular admin sees only their assigned orders and available orders in their vicinity
        try:
            # Get orders assigned to this admin
            assigned_orders = Order.query.filter_by(assigned_admin_id=current_user.id)
            
            # Get available orders in admin's vicinity
            available_orders = []
            if current_user.location and current_user.location.latitude and current_user.location.longitude:
                # Get all pending orders without assignment
                all_pending = Order.query.filter_by(status='Pending', assigned_admin_id=None).all()
                
                for order in all_pending:
                    if order.delivery_latitude and order.delivery_longitude:
                        distance = calculate_distance(
                            current_user.location.latitude, current_user.location.longitude,
                            order.delivery_latitude, order.delivery_longitude
                        )
                        if distance <= app.config['MAX_ASSIGNMENT_DISTANCE_KM']:
                            available_orders.append({
                                'order': order,
                                'distance': distance
                            })
            
            stats = {
                'total_orders': assigned_orders.count() or 0,
                'pending_orders': assigned_orders.filter_by(status='Pending').count() or 0,
                'processing_orders': assigned_orders.filter_by(status='Processing').count() or 0,
                'completed_orders': assigned_orders.filter_by(status='Completed').count() or 0,
                'cancelled_orders': assigned_orders.filter_by(status='Cancelled').count() or 0,
                'available_orders': len(available_orders),
                'recent_orders': assigned_orders.order_by(Order.created_at.desc()).limit(10).all(),
                'available_orders_list': available_orders
            }
            
            return render_template('admin_dashboard.html', stats=stats)
            
        except Exception as e:
            app.logger.error(f"Error in admin dashboard: {str(e)}")
            stats = {
                'total_orders': 0,
                'pending_orders': 0,
                'processing_orders': 0,
                'completed_orders': 0,
                'cancelled_orders': 0,
                'available_orders': 0,
                'recent_orders': [],
                'available_orders_list': []
            }
            return render_template('admin_dashboard.html', stats=stats)

    @app.route('/admin/orders')
    @login_required
    def admin_orders():
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
        
        page = request.args.get('page', 1, type=int)
        per_page = 10
        status_filter = request.args.get('status')
        search_query = request.args.get('search', '')
        sort = request.args.get('sort', 'created_at')
        direction = request.args.get('direction', 'desc')

        # Superadmin sees all orders, regular admins only see available orders in their vicinity
        if current_user.is_superadmin:
            query = Order.query
        else:
            # Regular admins see:
            # 1. Orders assigned to them (regardless of status)
            # 2. Available orders in their vicinity (Pending status, not assigned to anyone, within distance)
            query = Order.query.filter(
                (Order.assigned_admin_id == current_user.id) | 
                ((Order.status == 'Pending') & (Order.assigned_admin_id.is_(None)))
            )
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        if search_query:
            query = query.filter(
                Order.original_filename.ilike(f'%{search_query}%') |
                Order.customer.has(User.username.ilike(f'%{search_query}%'))
            )
        
        if sort == 'priority':
            if direction == 'asc':
                query = query.order_by(Order.is_rush.asc(), Order.priority_level.asc())
            else:
                query = query.order_by(Order.is_rush.desc(), Order.priority_level.desc())
        else:
            if direction == 'asc':
                query = query.order_by(Order.created_at.asc())
            else:
                query = query.order_by(Order.created_at.desc())
        
        orders = query.paginate(page=page, per_page=per_page)
        
        # For regular admins, filter available orders by distance
        available_orders_in_vicinity = []
        if not current_user.is_superadmin and current_user.location:
            for order in orders.items:
                if order.status == 'Pending' and not order.assigned_admin_id:
                    if order.delivery_latitude and order.delivery_longitude:
                        distance = calculate_distance(
                            current_user.location.latitude, current_user.location.longitude,
                            order.delivery_latitude, order.delivery_longitude
                        )
                        if distance <= app.config['MAX_ASSIGNMENT_DISTANCE_KM']:
                            setattr(order, 'distance', distance)
                            available_orders_in_vicinity.append(order)
        
        # Get counts for dashboard
        if current_user.is_superadmin:
            counts = {
                'all': Order.query.count(),
                'pending': Order.query.filter_by(status='Pending').count(),
                'processing': Order.query.filter_by(status='Processing').count(),
                'completed': Order.query.filter_by(status='Completed').count(),
                'cancelled': Order.query.filter_by(status='Cancelled').count()
            }
        else:
            counts = {
                'all': Order.query.filter(
                    (Order.assigned_admin_id == current_user.id) | 
                    ((Order.status == 'Pending') & (Order.assigned_admin_id.is_(None)))
                ).count(),
                'pending': Order.query.filter_by(status='Pending', assigned_admin_id=None).count(),
                'processing': Order.query.filter_by(status='Processing', assigned_admin_id=current_user.id).count(),
                'completed': Order.query.filter_by(status='Completed', assigned_admin_id=current_user.id).count(),
                'cancelled': Order.query.filter_by(status='Cancelled', assigned_admin_id=current_user.id).count()
            }
        
        # Get available admins for assignment (for superadmin)
        admins = User.query.filter_by(is_admin=True).all() if current_user.is_superadmin else []
        
        return render_template('admin_orders.html', 
                            orders=orders,
                            counts=counts,
                            status_filter=status_filter,
                            search_query=search_query,
                            sort_column=sort,
                            sort_direction=direction,
                            admins=admins,
                            available_orders_in_vicinity=available_orders_in_vicinity)

    @app.route('/admin/order/<int:order_id>')
    @login_required
    def view_order(order_id):
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
        
        order = Order.query.get_or_404(order_id)
        
        # Superadmin can view any order, regular admin can view their assigned orders or available orders in vicinity
        if not current_user.is_superadmin:
            if order.assigned_admin_id != current_user.id:
                # Check if order is in admin's vicinity
                if (not order.delivery_latitude or not order.delivery_longitude or
                    not current_user.location or not current_user.location.latitude or not current_user.location.longitude or
                    calculate_distance(
                        current_user.location.latitude, current_user.location.longitude,
                        order.delivery_latitude, order.delivery_longitude
                    ) > app.config['MAX_ASSIGNMENT_DISTANCE_KM']):
                    abort(403)
        
        # Get customer details
        customer = User.query.get(order.user_id)
        
        # Get assigned admin details if assigned
        assigned_admin = None
        if order.assigned_admin_id:
            assigned_admin = User.query.get(order.assigned_admin_id)
        
        # Get processed by admin details if processed
        processed_by = None
        if order.processed_by_id:
            processed_by = User.query.get(order.processed_by_id)
        
        # Calculate distance to this order if it has coordinates
        distance = None
        if (order.delivery_latitude and order.delivery_longitude and 
            current_user.location and current_user.location.latitude and current_user.location.longitude):
            distance = calculate_distance(
                current_user.location.latitude, current_user.location.longitude,
                order.delivery_latitude, order.delivery_longitude
            )
        
        # Calculate processing time if completed
        processing_time = None
        if order.processing_started_at and order.processing_completed_at:
            processing_time = order.processing_completed_at - order.processing_started_at
        
        admins = User.query.filter_by(is_admin=True).all() if current_user.is_superadmin else []
        
        return render_template('admin_order_detail.html', 
                            order=order, 
                            customer=customer,
                            assigned_admin=assigned_admin,
                            processed_by=processed_by,
                            admins=admins,
                            distance=distance,
                            processing_time=processing_time)

    @app.route('/admin/orders/<int:order_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_order(order_id):
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
            
        order = get_order_by_id(order_id)
        if not order:
            flash("Order not found.", "danger")
            return redirect(url_for('admin_orders'))

        # Regular admin can only edit their assigned orders
        if not current_user.is_superadmin and order.assigned_admin_id != current_user.id:
            abort(403)

        if request.method == 'POST':
            data = request.form
            update_order(order_id, data)
            flash("Order updated successfully!", "success")
            return redirect(url_for('view_order', order_id=order_id))
        
        admins = User.query.filter_by(is_admin=True).all() if current_user.is_superadmin else []
        return render_template('edit_order.html', order=order, admins=admins)

    # update order status
    @app.route('/admin/update_order_status/<int:order_id>', methods=['POST'])
    @login_required
    def update_order_status(order_id):
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
        
        order = Order.query.get_or_404(order_id)
        new_status = request.form['status']
        
        # Regular admin can only update their assigned orders
        if not current_user.is_superadmin and order.assigned_admin_id != current_user.id:
            abort(403)
        
        # Track when order is completed
        if new_status == 'Completed' and order.status != 'Completed':
            order.processing_completed_at = datetime.utcnow()
            order.processed_by_id = current_user.id  # Ensure processed_by is set
        
        order.status = new_status
        db.session.commit()
        
        flash(f'Order status updated to {new_status}', 'success')
        return redirect(url_for('admin_orders'))

    @app.route('/admin/update_status/<int:order_id>', methods=['POST'])
    @login_required
    def update_status(order_id):
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
        
        order = Order.query.get_or_404(order_id)
        
        # Regular admin can only update their assigned orders
        if not current_user.is_superadmin and order.assigned_admin_id != current_user.id:
            abort(403)
        
        order.status = request.form['status']
        db.session.commit()
        flash('Order status updated', 'success')
        return redirect(url_for('admin_orders'))

    # Super Admin specific routes
    @app.route('/superadmin/dashboard')
    @login_required
    def superadmin_dashboard():
        if not current_user.is_superadmin:
            abort(403)
        
        try:
            # Comprehensive superadmin statistics
            stats = {
                'total_orders': Order.query.count() or 0,
                'total_users': User.query.count() or 0,
                'total_admins': User.query.filter_by(is_admin=True).count() or 0,
                'pending_orders': Order.query.filter_by(status='Pending').count() or 0,
                'processing_orders': Order.query.filter_by(status='Processing').count() or 0,
                'completed_orders': Order.query.filter_by(status='Completed').count() or 0,
                'cancelled_orders': Order.query.filter_by(status='Cancelled').count() or 0,
                'recent_orders': Order.query.order_by(Order.created_at.desc()).limit(10).all()
            }
            
            # Revenue calculations (only for completed orders)
            today = datetime.today().date()
            stats['revenue_today'] = db.session.query(func.sum(Order.price))\
                                            .filter(Order.status == 'Completed')\
                                            .filter(func.date(Order.updated_at) == today)\
                                            .scalar() or 0
            
            current_month = datetime.today().month
            stats['revenue_month'] = db.session.query(func.sum(Order.price))\
                                            .filter(Order.status == 'Completed')\
                                            .filter(func.extract('month', Order.updated_at) == current_month)\
                                            .scalar() or 0
            
            # Top users by spending - specify the join condition explicitly
            stats['top_users'] = db.session.query(
                User.username,
                func.count(Order.id).label('order_count'),
                func.sum(Order.price).label('total_spent')
            ).join(Order, Order.user_id == User.id)\
            .filter(Order.status == 'Completed')\
            .group_by(User.id)\
            .order_by(func.sum(Order.price).desc())\
            .limit(5).all()
            
            # Enhanced Admin performance with detailed metrics including cancelled orders
            stats['admin_performance'] = db.session.query(
                User.username,
                func.count(Order.id).label('total_orders'),
                func.count(case((Order.status == 'Pending', Order.id))).label('pending_orders'),
                func.count(case((Order.status == 'Processing', Order.id))).label('processing_orders'),
                func.count(case((Order.status == 'Completed', Order.id))).label('completed_orders'),
                func.count(case((Order.status == 'Cancelled', Order.id))).label('cancelled_orders'),
                func.avg(case((Order.status == 'Completed', 
                            func.julianday(Order.processing_completed_at) - func.julianday(Order.processing_started_at)))).label('avg_completion_days')
            ).join(Order, Order.assigned_admin_id == User.id)\
            .filter(User.is_admin == True)\
            .group_by(User.id).all()
            
            return render_template('superadmin_dashboard.html', stats=stats)
            
        except Exception as e:
            # If there's any error, return basic stats
            app.logger.error(f"Error in superadmin dashboard: {str(e)}")
            stats = {
                'total_orders': 0,
                'total_users': 0,
                'total_admins': 0,
                'pending_orders': 0,
                'processing_orders': 0,
                'completed_orders': 0,
                'cancelled_orders': 0,
                'revenue_today': 0,
                'revenue_month': 0,
                'recent_orders': [],
                'top_users': [],
                'admin_performance': []
            }
            return render_template('superadmin_dashboard.html', stats=stats)

    @app.route('/superadmin/create_admin', methods=['GET', 'POST'])
    @login_required
    def create_admin():
        if not current_user.is_superadmin:
            abort(403)
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip()
            phone_number = request.form.get('phone_number', '').strip()
            address = request.form.get('address', '').strip()
            
            # Validation checks
            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return redirect(url_for('create_admin'))
                
            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'danger')
                return redirect(url_for('create_admin'))
            
            if email and User.query.filter_by(email=email).first():
                flash('Email already exists!', 'danger')
                return redirect(url_for('create_admin'))
            
            try:
                # Generate a secure one-time password if not provided
                if not password:
                    alphabet = string.ascii_letters + string.digits
                    password = ''.join(secrets.choice(alphabet) for _ in range(16))
                    flash(f'Auto-generated one-time password: {password}', 'info')
                
                new_admin = User(
                    username=username,
                    email=email if email else None,
                    full_name=full_name if full_name else None,
                    phone_number=phone_number if phone_number else None,
                    is_admin=True,
                    is_superadmin=False
                )
                new_admin.set_password(password, is_one_time=True)
                db.session.add(new_admin)
                db.session.commit()
                
                # Set admin location if address is provided
                if address:
                    latitude, longitude = get_coordinates_from_address(address)
                    if latitude is not None and longitude is not None:
                        new_admin.set_location(address, latitude, longitude)
                        db.session.commit()
                        flash(f'Admin location set: {address}', 'info')
                
                flash(f'Admin account "{username}" created successfully with one-time password!', 'success')
                return redirect(url_for('admin_users'))
                
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(url_for('create_admin'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating admin account: {str(e)}', 'danger')
                return redirect(url_for('create_admin'))
        
        return render_template('create_admin.html')

    @app.route('/superadmin/user/<int:user_id>')
    @login_required
    def user_detail(user_id):
        if not current_user.is_superadmin:
            abort(403)
        
        user = User.query.get_or_404(user_id)
        
        # Get user's order history
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
        
        # Calculate user statistics
        order_stats = {
            'total_orders': len(orders),
            'pending_orders': sum(1 for o in orders if o.status == 'Pending'),
            'processing_orders': sum(1 for o in orders if o.status == 'Processing'),
            'completed_orders': sum(1 for o in orders if o.status == 'Completed'),
            'cancelled_orders': sum(1 for o in orders if o.status == 'Cancelled'),
            'total_spent': sum(o.price for o in orders if o.status == 'Completed')
        }
        
        # Get account activity (recent orders for timeline)
        recent_activity = orders[:10]  # Last 10 orders
        
        return render_template('user_detail.html', 
                            user=user, 
                            orders=orders,
                            order_stats=order_stats,
                            recent_activity=recent_activity)

    @app.route('/admin/users')
    @login_required
    def admin_users():
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)

        users = User.query.order_by(User.created_at.desc()).all()
        
        # For superadmin, include password information
        user_data = []
        for user in users:
            user_info = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_superadmin': user.is_superadmin,
                'created_at': user.created_at,
                'password_changed_at': user.password_changed_at,
                'is_one_time_password': user.is_one_time_password,
                'requires_password_change': user.is_admin and user.is_one_time_password,
                'has_location': user.location_set,
                'location': user.location.address if user.location else 'Not set'
            }
            user_data.append(user_info)

        return render_template('admin_users.html', users=user_data)

    @app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        if not current_user.is_superadmin:
            abort(403)

        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("You cannot delete your own account.", "danger")
            return redirect(url_for('admin_users'))
        
        if user.is_superadmin:
            flash("Cannot delete superadmin accounts.", "danger")
            return redirect(url_for('admin_users'))

        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' deleted successfully.", "success")
        return redirect(url_for('admin_users'))

    @app.route('/download/<int:order_id>')
    @login_required
    def download_order(order_id):
        order = Order.query.get_or_404(order_id)
        
        # Superadmin can download any file
        if current_user.is_superadmin:
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                order.file_name,
                as_attachment=True,
                download_name=order.original_filename
            )
        
        # Regular admins can only download orders in their vicinity or assigned to them
        if current_user.is_admin:
            # Check if order is assigned to this admin
            if order.assigned_admin_id == current_user.id:
                return send_from_directory(
                    app.config['UPLOAD_FOLDER'],
                    order.file_name,
                    as_attachment=True,
                    download_name=order.original_filename
                )
            
            # Check if order is in admin's vicinity
            if (order.delivery_latitude and order.delivery_longitude and
                current_user.location and current_user.location.latitude and current_user.location.longitude):
                distance = calculate_distance(
                    current_user.location.latitude, current_user.location.longitude,
                    order.delivery_latitude, order.delivery_longitude
                )
                if distance <= app.config['MAX_ASSIGNMENT_DISTANCE_KM'] and order.status == 'Pending':
                    # Assign order to this admin and update status
                    order.status = 'Processing'
                    order.assigned_admin_id = current_user.id
                    order.processed_by_id = current_user.id
                    order.processing_started_at = datetime.utcnow()
                    db.session.commit()
                    
                    flash('Order assigned to you and status updated to Processing', 'success')
                    
                    return send_from_directory(
                        app.config['UPLOAD_FOLDER'],
                        order.file_name,
                        as_attachment=True,
                        download_name=order.original_filename
                    )
            
            flash('You do not have permission to access this order.', 'warning')
            return redirect(url_for('admin_orders'))
        
        # Regular users can only download their own orders
        if order.user_id != current_user.id:
            abort(403)
        
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            order.file_name,
            as_attachment=True,
            download_name=order.original_filename
        )

    @app.route('/forgot_password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            
            if user:
                # Generate reset token
                token = user.generate_reset_token()
                db.session.commit()
                
                # In a real application, you would send an email here
                # For now, we'll just show the reset link
                reset_url = url_for('reset_password', token=token, _external=True)
                flash(f'Password reset link: {reset_url}', 'info')
                return redirect(url_for('login'))
            else:
                flash('Username not found', 'danger')
        
        return render_template('forgot_password.html')

    @app.route('/reset_password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or user.reset_token_expires < datetime.utcnow():
            flash('Invalid or expired reset token', 'danger')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return render_template('reset_password.html', token=token)
            
            try:
                user.set_password(password)
                user.clear_reset_token()
                user.is_one_time_password = False
                db.session.commit()
                
                flash('Password reset successfully! Please login with your new password.', 'success')
                return redirect(url_for('login'))
                
            except ValueError as e:
                flash(str(e), 'danger')
        
        return render_template('reset_password.html', token=token)

    @app.route('/change_password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        # Check if password change is required (one-time password)
        require_change = session.get('require_password_change')
        if not require_change or require_change != current_user.id:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'danger')
                return render_template('change_password.html')
            
            if new_password != confirm_password:
                flash('New passwords do not match!', 'danger')
                return render_template('change_password.html')
            
            try:
                current_user.set_password(new_password)
                current_user.is_one_time_password = False
                session.pop('require_password_change', None)
                db.session.commit()
                
                flash('Password changed successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except ValueError as e:
                flash(str(e), 'danger')
        
        return render_template('change_password.html')

    @app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
    @login_required
    def admin_reset_password(user_id):
        if not current_user.is_superadmin:
            abort(403)
        
        user = User.query.get_or_404(user_id)
        
        # Generate a secure one-time password
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(16))
        
        user.set_password(new_password, is_one_time=True)
        db.session.commit()
        
        flash(f'Password reset for {user.username}. New one-time password: {new_password}', 'info')
        return redirect(url_for('admin_users'))

    @app.route('/profile')
    @login_required
    def profile():
        # Get the current user's orders for the profile
        user_orders = Order.query.filter_by(user_id=current_user.id)\
                                .order_by(Order.created_at.desc())\
                                .all()
        
        # Calculate user statistics
        order_stats = {
            'total_orders': len(user_orders),
            'pending_orders': sum(1 for o in user_orders if o.status == 'Pending'),
            'processing_orders': sum(1 for o in user_orders if o.status == 'Processing'),
            'completed_orders': sum(1 for o in user_orders if o.status == 'Completed'),
            'cancelled_orders': sum(1 for o in user_orders if o.status == 'Cancelled'),
            'total_spent': sum(o.price for o in user_orders if o.status == 'Completed')
        }
        
        return render_template('profile.html', 
                            user=current_user,
                            orders=user_orders,
                            order_stats=order_stats)
    
    @app.route('/superadmin/admin/<int:admin_id>')
    @login_required
    def admin_detail(admin_id):
        if not current_user.is_superadmin:
            abort(403)
        
        admin = User.query.get_or_404(admin_id)
        
        # Verify this is actually an admin
        if not admin.is_admin and not admin.is_superadmin:
            flash('This user is not an administrator', 'warning')
            return redirect(url_for('admin_users'))
        
        # Get admin's assigned orders
        assigned_orders = Order.query.filter_by(assigned_admin_id=admin_id).order_by(Order.created_at.desc()).all()
        
        # Get orders processed by this admin
        processed_orders = Order.query.filter_by(processed_by_id=admin_id).order_by(Order.created_at.desc()).all()
        
        # Calculate admin performance statistics
        performance_stats = {
            'total_assigned': len(assigned_orders),
            'total_processed': len(processed_orders),
            'completed_orders': sum(1 for o in processed_orders if o.status == 'Completed'),
            'pending_orders': sum(1 for o in assigned_orders if o.status == 'Pending'),
            'processing_orders': sum(1 for o in assigned_orders if o.status == 'Processing'),
        }
        
        return render_template('admin_detail.html', 
                            admin=admin,
                            assigned_orders=assigned_orders,
                            processed_orders=processed_orders,
                            performance_stats=performance_stats)
    
    @app.route('/admin/assign_order/<int:order_id>', methods=['POST'])
    @login_required
    def assign_order(order_id):
        if not current_user.is_superadmin:
            abort(403)
        
        order = Order.query.get_or_404(order_id)
        admin_id = request.form.get('admin_id')
        
        if admin_id:
            admin = User.query.get(admin_id)
            if admin and (admin.is_admin or admin.is_superadmin):
                order.assigned_admin_id = admin_id
                order.status = 'Processing'
                order.processing_started_at = datetime.utcnow()
                db.session.commit()
                flash(f'Order assigned to {admin.username}', 'success')
            else:
                flash('Invalid admin selected', 'danger')
        else:
            # Unassign order
            order.assigned_admin_id = None
            order.status = 'Pending'
            order.processing_started_at = None
            db.session.commit()
            flash('Order unassigned', 'success')
        
        return redirect(url_for('admin_orders'))

    @app.route('/admin/set_location', methods=['GET', 'POST'])
    @login_required
    def set_admin_location():
        if not current_user.is_admin:
            abort(403)
        
        if request.method == 'POST':
            address = request.form.get('address', '').strip()
            
            if address:
                latitude, longitude = get_coordinates_from_address(address)
                if latitude is not None and longitude is not None:
                    current_user.set_location(address, latitude, longitude)
                    db.session.commit()
                    flash('Your location has been updated successfully!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Could not determine coordinates for this address. Please try a more specific address.', 'danger')
            else:
                flash('Please enter a valid address', 'danger')
        
        return render_template('set_location.html')

    @app.route('/detect_pages', methods=['POST'])
    @login_required
    def detect_pages():
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        try:
            file_content = file.read()
            page_count = count_pages(None, file_content)
            
            if page_count is not None:
                return jsonify({'success': True, 'page_count': page_count})
            else:
                return jsonify({'success': False, 'error': 'Could not detect page count'})
                
        except Exception as e:
            app.logger.error(f"Page detection error: {str(e)}")
            return jsonify({'success': False, 'error': 'Error processing file'})

    @app.route('/cancel_upload')
    @login_required
    def cancel_upload():
        # Clean up any uploaded temporary files
        if 'uploaded_file' in session:
            try:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], session['uploaded_file']['filename'])
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                app.logger.error(f"Error cleaning up file: {str(e)}")
            
            session.pop('uploaded_file', None)
        
        return redirect(url_for('dashboard'))

    @app.route('/api/calculate_price', methods=['POST'])
    @login_required
    def calculate_price_api():
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['pages', 'copies', 'paper_type', 'paper_size', 'color', 'priority']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing field: {field}'}), 400
            
            # Parse and validate inputs
            pages = int(data['pages'])
            copies = int(data['copies'])
            paper_type = data['paper_type']
            paper_size = data['paper_size']
            color = data['color'] == 'true'
            priority = data['priority']
            
            if pages < 1 or pages > 500:
                return jsonify({'error': 'Invalid page count (1-500)'}), 400
            if copies < 1 or copies > 100:
                return jsonify({'error': 'Invalid copies count (1-100)'}), 400
            
            # Calculate price using your existing function
            total_price = calculate_price(
                pages, copies, paper_type, paper_size, color, priority
            )
            
            return jsonify({
                'success': True,
                'price': total_price,
                'formatted_price': f"UGX {total_price:,.0f}".replace(",", " ")
            })
            
        except Exception as e:
            app.logger.error(f"Price calculation error: {str(e)}")
            return jsonify({'error': 'Error calculating price'}), 500
    
    @app.route('/admin/complete_order/<int:order_id>', methods=['POST'])
    @login_required
    def complete_order_admin(order_id):
        if not (current_user.is_admin or current_user.is_superadmin):
            abort(403)
        
        order = Order.query.get_or_404(order_id)
        
        # Check if admin can access this order
        if not current_user.is_superadmin and order.assigned_admin_id != current_user.id:
            abort(403)
        
        if order.status != 'Processing':
            flash('Only orders in Processing status can be completed.', 'warning')
            return redirect(url_for('view_order', order_id=order_id))
        
        # Get completion notes from form
        completion_notes = request.form.get('completion_notes', '').strip()
        
        # Update order status to completed
        order.status = 'Completed'
        order.processing_completed_at = datetime.utcnow()
        order.processed_by_id = current_user.id
        
        # Add completion notes to admin notes
        if completion_notes:
            if order.admin_notes:
                order.admin_notes += f"\n\nCompletion Notes ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')}): {completion_notes}"
            else:
                order.admin_notes = f"Completion Notes ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')}): {completion_notes}"
        
        # Update payment status if it was pending
        if order.payment_status == 'Pending' and order.payment_method != 'Pay on Delivery':
            order.payment_status = 'Completed'
        
        db.session.commit()
        
        flash(f'Order #{order.id} has been marked as completed!', 'success')
        return redirect(url_for('view_order', order_id=order_id))

    @app.route('/my_order/<int:order_id>')
    @login_required
    def view_my_order(order_id):
        # Regular users can only view their own orders
        order = Order.query.get_or_404(order_id)
        
        if order.user_id != current_user.id:
            abort(403)
        
        # Get assigned admin details if assigned
        assigned_admin = None
        if order.assigned_admin_id:
            assigned_admin = User.query.get(order.assigned_admin_id)
        
        # Get processed by admin details if processed
        processed_by = None
        if order.processed_by_id:
            processed_by = User.query.get(order.processed_by_id)
        
        # Calculate processing time if completed
        processing_time = None
        if order.processing_started_at and order.processing_completed_at:
            processing_time = order.processing_completed_at - order.processing_started_at
        
        return render_template('client_order_detail.html', 
                            order=order,
                            assigned_admin=assigned_admin,
                            processed_by=processed_by,
                            processing_time=processing_time)
    
    @app.route('/cancel_my_order/<int:order_id>', methods=['POST'])
    @login_required
    def cancel_my_order(order_id):
        order = Order.query.get_or_404(order_id)
        
        if order.user_id != current_user.id:
            abort(403)
        
        if order.status != 'Pending':
            flash('Only pending orders can be cancelled.', 'warning')
            return redirect(url_for('view_my_order', order_id=order_id))
        
        # Update order status
        order.status = 'Cancelled'
        order.cancelled_at = datetime.utcnow()
        order.cancellation_reason = request.form.get('cancellation_reason', '').strip()
        
        db.session.commit()
        
        flash('Your order has been cancelled successfully.', 'success')
        return redirect(url_for('my_orders'))

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

# Flask-Login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create app instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)