import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime, timedelta
from dotenv import load_dotenv

# 1. Load Environment Variables
load_dotenv()

app = Flask(__name__)

# --- KONFIGURASI APP ---
app.secret_key = os.getenv('SECRET_KEY', 'nailcare_secretkey')

# Database Config - Menggunakan database nail_beauty
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root@localhost/nail_beauty"
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
    name = db.Column(db.String(100), nullable=True) 
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True) # Dibuat True agar Google Auth lancar
    google_id = db.Column(db.String(255), nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_json(self):
        return {"id": self.id, "name": self.name or "User", "email": self.email}
    
    
class Tip(db.Model):
    __tablename__ = "tips"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # image_url tetap ada di DB agar tidak error, tapi tidak dikirim ke JSON/Frontend
    image_url = db.Column(db.String(255), nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_json(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

# ==========================================
#                AUTH ROUTES 
# ==========================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name', '')

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

    if not user:
        # Jika user belum ada, buat baru
        user = User(
            email=email, 
            name=name, 
            google_id=google_id, 
            password="GOOGLE_USER" # Tambahkan ini supaya tidak Error 1048
        )
        db.session.add(user)
        db.session.commit()
    
    # Return data user sesuai format Gambar 1 (id, name, email)
    return jsonify({
        "status": "success",
        "message": "Login Google Berhasil",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email
        }
    }), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if user:
        user.password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
        db.session.commit()
        return jsonify({"message": "Password berhasil diperbarui"}), 200
    return jsonify({"message": "Email tidak ditemukan"}), 404

# ==========================================
#                TIPS API
# ==========================================

@app.route('/api/tips', methods=['GET'])
def get_tips():
    tips = Tip.query.order_by(Tip.created_at.desc()).all()
    return jsonify([tip.to_json() for tip in tips]), 200

# ==========================================
#                ADMIN ROUTES 
# ==========================================

@app.route('/')
def home():
    return redirect(url_for('admin_login'))

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
    return render_template('admin.html', 
                           users=users, 
                           tips=tips, 
                           total_users=len(users), 
                           total_tips=len(tips))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# --- CRUD USER (ADMIN) ---

@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if User.query.filter_by(email=email).first():
        flash("Email sudah terdaftar!", "danger")
        return redirect(url_for('admin_dashboard'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    flash(f"User {name} berhasil ditambahkan!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:id>')
def delete_user(id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User berhasil dihapus!", "warning")
    return redirect(url_for('admin_dashboard'))

# --- CRUD TIPS (ADMIN) ---

@app.route('/admin/add-tip', methods=['POST'])
def admin_add_tip():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    new_tip = Tip(title=request.form.get('title'), 
                  content=request.form.get('content'))
    db.session.add(new_tip)
    db.session.commit()
    flash("Tips berhasil ditambahkan!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-tip/<int:id>')
def delete_tip(id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    tip = Tip.query.get(id)
    if tip:
        db.session.delete(tip)
        db.session.commit()
        flash("Tips berhasil dihapus!", "warning")
    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001, host='0.0.0.0')