from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import Order, db
from app.utils.pricing import calculate_price
from app.utils.file_handling import handle_file_upload
from datetime import datetime

orders_bp = Blueprint('orders', __name__)

@orders_bp.route('/dashboard')
@login_required
def dashboard():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('orders/dashboard.html', orders=orders)

@orders_bp.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        try:
            file = request.files['file']
            filename = handle_file_upload(file, current_user.id)
            
            order = Order(
                user_id=current_user.id,
                file_name=filename,
                original_filename=file.filename,
                pages=int(request.form['pages']),
                color=request.form.get('color') == 'on',
                price=calculate_price(
                    int(request.form['pages']),
                    int(request.form.get('copies', 1)),
                    request.form['paper_type'],
                    request.form['paper_size'],
                    request.form.get('color') == 'on',
                    request.form['priority']
                ),
                created_at=datetime.utcnow()
            )
            db.session.add(order)
            db.session.commit()
            flash('Order submitted!', 'success')
            return redirect(url_for('orders.dashboard'))
            
        except Exception as e:
            flash(str(e), 'danger')
    
    return render_template('orders/submit.html')