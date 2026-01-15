import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests

# 1. Load Environment Variables
load_dotenv()

app = Flask(__name__)

# --- KONFIGURASI APP ---
app.secret_key = os.getenv('SECRET_KEY', 'nailcare_secretkey')

# Database Config (MySQL via XAMPP)
db_host = os.getenv('DB_HOST', 'localhost')
db_user = os.getenv('DB_USER', 'root')
db_pass = os.getenv('DB_PASS', '') 
db_name = os.getenv('DB_NAME', 'nail_beauty')
db_port = os.getenv('DB_PORT', '3306')

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Config
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Inisialisasi Library
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# ==========================================
#              DATABASE MODELS
# ==========================================

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    google_id = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email
        }

class Tip(db.Model):
    __tablename__ = "tips"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_json(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "image_url": self.image_url,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

# ==========================================
#                AUTH ROUTES 
# ==========================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email sudah terdaftar"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registrasi berhasil"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and user.password and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            "message": "Login berhasil",
            "access_token": access_token,
            "user": user.to_json()
        }), 200
    return jsonify({"message": "Email atau password salah"}), 401

@app.route('/api/google-auth', methods=['POST'])
def google_auth():
    data = request.json
    email = data.get('email')
    name = data.get('name')
    google_id = data.get('google_id')

    user = User.query.filter_by(email=email).first()

    if user:
        if not user.google_id:
            user.google_id = google_id
            db.session.commit()
    else:
        user = User(name=name, email=email, google_id=google_id, password='')
        db.session.add(user)
        db.session.commit()
    
    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "Login Google Berhasil",
        "access_token": access_token,
        "user": user.to_json()
    }), 200

# ==========================================
#                ADMIN ROUTES 
# ==========================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('username') == "admin" and request.form.get('password') == "admin123":
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash("Username atau Password salah!", "danger")
    return render_template('admin_login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    users = User.query.all()
    tips = Tip.query.all()
    return render_template('admin.html', users=users, tips=tips, 
                           total_users=len(users), total_tips=len(tips))

@app.route('/admin/add-tip', methods=['POST'])
def admin_add_tip():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    new_tip = Tip(title=request.form.get('title'), 
                  content=request.form.get('content'),
                  image_url=request.form.get('image_url'))
    db.session.add(new_tip)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-tip/<int:id>')
def delete_tip(id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    tip = Tip.query.get(id)
    if tip:
        db.session.delete(tip)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:id>')
def delete_user(id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# ==========================================
#                MOBILE API 
# ==========================================

@app.route('/api/tips', methods=['GET'])
def get_tips():
    tips = Tip.query.order_by(Tip.created_at.desc()).all()
    return jsonify([tip.to_json() for tip in tips]), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if not user: return jsonify({"message": "Email tidak ditemukan"}), 404
    
    user.password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    db.session.commit()
    return jsonify({"message": "Password berhasil diubah"}), 200

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001, host='0.0.0.0')