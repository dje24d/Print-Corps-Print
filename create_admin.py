# create_admin.py
import os
import sys
from app import create_app, db
from app.models import User

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

def create_admin():
    app = create_app()
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                is_admin=True,
                is_superadmin=True
            )
            admin.set_password('admin123456')  # Use the strong password from your config
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created successfully!")
            print(f"Username: admin")
            print(f"Password: admin123456")
        else:
            print("ℹ️ Admin user already exists")

if __name__ == '__main__':
    create_admin()