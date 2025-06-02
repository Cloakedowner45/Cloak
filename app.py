from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Use something strong here
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///licenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
limiter = Limiter(app, key_func=get_remote_address)

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    valid = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)
    hardware_id = db.Column(db.String(100), nullable=True)

@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('login.html')
    return render_template('admin.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'admin' and password == 'password':
        session['logged_in'] = True
        return redirect(url_for('index'))
    return 'Invalid credentials', 403

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/generate', methods=['POST'])
def generate_key():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    new_key = secrets.token_hex(16)
    expires_at = datetime.utcnow() + timedelta(days=30)
    license_key = LicenseKey(key=new_key, expires_at=expires_at)
    db.session.add(license_key)
    db.session.commit()
    return jsonify({'key': new_key, 'expires_at': expires_at.isoformat()})

@app.route('/api/check_key', methods=['POST'])
@limiter.limit("5 per minute")
def check_key():
    data = request.get_json()
    key = data.get('key')
    hwid = data.get('hwid')
    request_ip = request.remote_addr

    if not key:
        return jsonify({'valid': False, 'error': 'Missing key'}), 400

    license_key = LicenseKey.query.filter_by(key=key).first()
    if not license_key or not license_key.valid:
        return jsonify({'valid': False, 'error': 'Invalid key'}), 403

    if license_key.expires_at and license_key.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'error': 'Key expired'}), 403

    if license_key.ip_address and license_key.ip_address != request_ip:
        return jsonify({'valid': False, 'error': 'Key locked to another IP'}), 403

    if license_key.hardware_id and hwid and license_key.hardware_id != hwid:
        return jsonify({'valid': False, 'error': 'Key locked to another machine'}), 403

    if not license_key.ip_address:
        license_key.ip_address = request_ip
    if hwid and not license_key.hardware_id:
        license_key.hardware_id = hwid
    db.session.commit()

    return jsonify({'valid': True})
