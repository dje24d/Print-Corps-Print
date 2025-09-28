import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///print_management.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Payment processors
    MTN_MERCHANT_CODE = os.getenv('MTN_MERCHANT_CODE')
    AIRTEL_MERCHANT_ID = os.getenv('AIRTEL_MERCHANT_ID')
    
    # Business rules
    MINIMUM_DEPOSIT = 1000  # UGX
    CURRENCY = 'UGX'
    
    # File uploads
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Admin
    INITIAL_ADMIN_USERNAME = os.getenv('INITIAL_ADMIN_USERNAME', 'admin')
    INITIAL_ADMIN_PASSWORD = os.getenv('INITIAL_ADMIN_PASSWORD', 'admin123456')