from datetime import datetime
from enum import Enum
from app.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class Role(Enum):
    USER = 'user'
    ADMIN = 'admin'
    SUPERADMIN = 'superadmin'

class OrderStatus(Enum):
    PENDING = 'Pending'
    PROCESSING = 'Processing'
    COMPLETED = 'Completed'
    FAILED = 'Failed'

class PaymentStatus(Enum):
    PENDING = 'Pending'
    COMPLETED = 'Completed'
    FAILED = 'Failed'
    REFUNDED = 'Refunded'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum(Role), default=Role.USER)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    orders = db.relationship('Order', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_name = db.Column(db.String(200))
    original_filename = db.Column(db.String(200))
    file_path = db.Column(db.String(500))
    pages = db.Column(db.Integer)
    color = db.Column(db.Boolean, default=False)
    status = db.Column(db.Enum(OrderStatus), default=OrderStatus.PENDING)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    price = db.Column(db.Numeric(10, 2))
    payment_status = db.Column(db.String(20), default='Pending')
    transaction_id = db.Column(db.String(100))
    payment_method = db.Column(db.String(50))

class PaymentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    amount = db.Column(db.Numeric(10, 2))
    status = db.Column(db.Enum(PaymentStatus), default=PaymentStatus.PENDING)
    payment_method = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    completed_at = db.Column(db.DateTime)