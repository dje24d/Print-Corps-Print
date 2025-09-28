import os
from werkzeug.utils import secure_filename
from flask import current_app

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def handle_file_upload(file, user_id):
    if not allowed_file(file.filename):
        raise ValueError("Invalid file type")
    
    filename = secure_filename(f"user_{user_id}_{file.filename}")
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filename