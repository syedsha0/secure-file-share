from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_files.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/secure_file_share.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Secure File Share startup')

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Generate encryption key
def get_encryption_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    files = db.relationship('File', backref='owner', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    shares = db.relationship('FileShare', backref='file', lazy='dynamic', cascade="all, delete-orphan")

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    share_date = db.Column(db.DateTime, default=datetime.utcnow)
    can_edit = db.Column(db.Boolean, default=False)
    shared_with = db.relationship('User', backref='shared_files')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path, output_path=None):
    if output_path is None:
        output_path = file_path + '.decrypted'
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
    return output_path

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
        
        if user_exists:
            flash('Username already exists.')
            return redirect(url_for('register'))
        if email_exists:
            flash('Email already registered.')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        app.logger.info(f'User {username} logged in')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    my_files = File.query.filter_by(owner_id=current_user.id).all()
    shared_with_me = FileShare.query.filter_by(shared_with_id=current_user.id).all()
    return render_template('dashboard.html', my_files=my_files, shared_with_me=shared_with_me)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file:
            original_filename = secure_filename(file.filename)
            file_uuid = str(uuid.uuid4())
            filename = f"{file_uuid}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            file.save(file_path)
            file_size = os.path.getsize(file_path)
            
            # Encrypt the file
            encrypt_file(file_path)
            
            new_file = File(
                filename=filename,
                original_filename=original_filename,
                file_path=file_path,
                file_size=file_size,
                owner_id=current_user.id,
                is_encrypted=True
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            flash('File uploaded successfully')
            app.logger.info(f'User {current_user.username} uploaded file: {original_filename}')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user has permission to download
    if file.owner_id != current_user.id and not FileShare.query.filter_by(
            file_id=file.id, shared_with_id=current_user.id).first():
        flash('You do not have permission to download this file')
        return redirect(url_for('dashboard'))
    
    if file.is_encrypted:
        temp_path = f"/tmp/{uuid.uuid4()}_{file.original_filename}"
        decrypt_file(file.file_path, temp_path)
        app.logger.info(f'User {current_user.username} downloaded file: {file.original_filename}')
        return send_file(temp_path, as_attachment=True, download_name=file.original_filename)
    else:
        return send_file(file.file_path, as_attachment=True, download_name=file.original_filename)

@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id:
        flash('You do not have permission to share this file')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        can_edit = True if request.form.get('can_edit') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('User not found')
            return redirect(url_for('share_file', file_id=file_id))
        
        if user.id == current_user.id:
            flash('You cannot share a file with yourself')
            return redirect(url_for('share_file', file_id=file_id))
        
        existing_share = FileShare.query.filter_by(
            file_id=file.id, shared_with_id=user.id).first()
        
        if existing_share:
            flash('File already shared with this user')
            return redirect(url_for('share_file', file_id=file_id))
        
        new_share = FileShare(
            file_id=file.id,
            shared_with_id=user.id,
            can_edit=can_edit
        )
        
        db.session.add(new_share)
        db.session.commit()
        
        flash(f'File shared with {username}')
        app.logger.info(f'User {current_user.username} shared file {file.original_filename} with {username}')
        return redirect(url_for('dashboard'))
    
    return render_template('share.html', file=file)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id:
        flash('You do not have permission to delete this file')
        return redirect(url_for('dashboard'))
    
    # Delete the actual file
    if os.path.exists(file.file_path):
        os.remove(file.file_path)
    
    # Delete from database
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully')
    app.logger.info(f'User {current_user.username} deleted file: {file.original_filename}')
    return redirect(url_for('dashboard'))

@app.route('/revoke/<int:share_id>')
@login_required
def revoke_access(share_id):
    share = FileShare.query.get_or_404(share_id)
    file = File.query.get(share.file_id)
    
    if file.owner_id != current_user.id:
        flash('You do not have permission to revoke access')
        return redirect(url_for('dashboard'))
    
    shared_with = User.query.get(share.shared_with_id).username
    
    db.session.delete(share)
    db.session.commit()
    
    flash(f'Access revoked for {shared_with}')
    app.logger.info(f'User {current_user.username} revoked access for {shared_with} to file {file.original_filename}')
    return redirect(url_for('dashboard'))

# API endpoints for potential frontend integration
@app.route('/api/files')
@login_required
def api_files():
    my_files = File.query.filter_by(owner_id=current_user.id).all()
    files_data = [{
        'id': file.id,
        'filename': file.original_filename,
        'size': file.file_size,
        'upload_date': file.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
        'is_encrypted': file.is_encrypted
    } for file in my_files]
    
    return jsonify({'files': files_data})

@app.route('/api/shared')
@login_required
def api_shared():
    shared_with_me = FileShare.query.filter_by(shared_with_id=current_user.id).all()
    shared_data = [{
        'id': share.id,
        'file_id': share.file_id,
        'filename': share.file.original_filename,
        'owner': User.query.get(share.file.owner_id).username,
        'share_date': share.share_date.strftime('%Y-%m-%d %H:%M:%S'),
        'can_edit': share.can_edit
    } for share in shared_with_me]
    
    return jsonify({'shared_files': shared_data})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)

