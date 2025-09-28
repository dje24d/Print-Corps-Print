# config.py
import os

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///db.sqlite'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Uganda Mobile Money Settings
    MTN_MERCHANT_CODE = os.environ.get('MTN_MERCHANT_CODE', 'YOUR_MTN_CODE')  # From MTN MoMo API
    AIRTEL_MERCHANT_ID = os.environ.get('AIRTEL_MERCHANT_ID', 'YOUR_AIRTEL_ID')  # From Airtel Money
    
    # Payment defaults (UGX)
    MINIMUM_DEPOSIT = 1000  # Minimum payment amount in UGX
    CURRENCY = 'UGX'
    
    # File uploads
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
    
    # Admin credentials
    INITIAL_ADMIN_USERNAME = os.environ.get('INITIAL_ADMIN_USERNAME')
    INITIAL_ADMIN_PASSWORD = os.environ.get('INITIAL_ADMIN_PASSWORD')