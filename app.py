import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests

# 1. Load Environment Variables
load_dotenv()

app = Flask(__name__)

# --- KONFIGURASI APP ---
app.secret_key = os.getenv('SECRET_KEY', 'nailcare_secretkey')

db_host = os.getenv('DB_HOST', 'localhost')
db_user = os.getenv('DB_USER', 'root')
db_pass = os.getenv('DB_PASS', '') 
db_name = os.getenv('DB_NAME', 'nail_beauty')
db_port = os.getenv('DB_PORT', '3306')

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default-secret-key')
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
        return {"id": self.id, "name": self.name, "email": self.email}

class Tip(db.Model):
    __tablename__ = "tips"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_json(self):
        return {"id": self.id, "title": self.title, "content": self.content, "created_at": self.created_at}

# ==========================================
#                AUTH ROUTES 
# ==========================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    new_user = User(name=data.get('name'), email=data.get('email'), password=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Registrasi berhasil"}), 201
    except:
        return jsonify({"message": "Email sudah terdaftar"}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        access_token = create_access_token(identity=user.id)
        return jsonify({"message": "Login berhasil", "access_token": access_token, "user": user.to_json()}), 200
    return jsonify({"message": "Email atau password salah"}), 401

@app.route('/api/google-auth', methods=['POST'])
def google_auth():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if not user:
        user = User(name=data.get('name'), email=data.get('email'), google_id=data.get('google_id'), password='')
        db.session.add(user)
        db.session.commit()
    access_token = create_access_token(identity=user.id)
    return jsonify({"message": "Login Google Berhasil", "access_token": access_token, "user": user.to_json()}), 200

@app.route('/api/nearby-salons', methods=['GET'])
def get_nearby_salons():
    lat = float(request.args.get('lat', -6.86))
    lng = float(request.args.get('lng', 109.13))
    salons = [
        {"name": "Dummy Salon A", "address": "Jl. Mawar No. 10", "rating": 4.5, "lat": lat + 0.002, "lng": lng + 0.002, "place_id": "d1"},
        {"name": "Dummy Salon B", "address": "Jl. Sudirman No. 25", "rating": 4.8, "lat": lat - 0.003, "lng": lng - 0.001, "place_id": "d2"}
    ]
    return jsonify(salons), 200

# ==========================================
#              ADMIN & TIPS ROUTES 
# ==========================================

@app.route('/api/tips', methods=['GET'])
def get_tips():
    tips = Tip.query.all()
    return jsonify([tip.to_json() for tip in tips]), 200

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('admin.html', users=User.query.all(), tips=Tip.query.all(), 
                           total_users=User.query.count(), total_tips=Tip.query.count())

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('username') == "admin" and request.form.get('password') == "admin123":
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash("Username atau Password salah!", "danger")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# --- FUNGSI CRUD ADMIN ---

@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    hashed_password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
    new_user = User(name=request.form.get('name'), email=request.form.get('email'), password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    flash("User berhasil ditambahkan!", "success")
    return redirect(url_for('admin_dashboard'))

# FIX: Fungsi delete_user yang tadinya hilang sehingga bikin BuildError
@app.route('/admin/delete-user/<int:id>')
def delete_user(id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User berhasil dihapus!", "warning")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add-tip', methods=['POST'])
def admin_add_tip():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    new_tip = Tip(title=request.form.get('title'), content=request.form.get('content'))
    db.session.add(new_tip)
    db.session.commit()
    flash("Tips dipublikasikan!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-tip/<int:id>')
def delete_tip(id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    tip = Tip.query.get(id)
    if tip:
        db.session.delete(tip)
        db.session.commit()
        flash("Tips dihapus!", "warning")
    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001, host='0.0.0.0')