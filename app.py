from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_this_to_a_random_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keys.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'admin' or 'user'

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(32), unique=True, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # week, month, lifetime
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_suspended = db.Column(db.Boolean, default=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    user = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(user, action):
    db.session.add(AuditLog(user=user, action=action))
    db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            log_action(user.username, 'Logged in')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.username, 'Logged out')
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    keys = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    users = User.query.all() if current_user.role == 'admin' else []
    return render_template('dashboard.html', keys=keys, users=users)

@app.route('/generate_key', methods=['POST'])
@login_required
def generate_key():
    key_type = request.form.get('type')
    if key_type not in ['week', 'month', 'lifetime']:
        flash('Invalid key type selected')
        return redirect(url_for('dashboard'))

    new_key = secrets.token_hex(8)

    expires = None
    if key_type == 'week':
        expires = datetime.utcnow() + timedelta(weeks=1)
    elif key_type == 'month':
        expires = datetime.utcnow() + timedelta(days=30)

    license_key = LicenseKey(key=new_key, type=key_type, expires_at=expires)
    db.session.add(license_key)
    db.session.commit()
    log_action(current_user.username, f'Generated {key_type} key: {new_key}')
    flash(f'New {key_type} key generated: {new_key}')
    return redirect(url_for('dashboard'))

@app.route('/delete_key/<int:key_id>', methods=['POST'])
@login_required
def delete_key(key_id):
    license_key = LicenseKey.query.get_or_404(key_id)
    db.session.delete(license_key)
    db.session.commit()
    log_action(current_user.username, f'Deleted key: {license_key.key}')
    flash('License key deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/toggle_suspend_key/<int:key_id>', methods=['POST'])
@login_required
def toggle_suspend_key(key_id):
    key = LicenseKey.query.get_or_404(key_id)
    key.is_suspended = not key.is_suspended
    db.session.commit()
    status = 'Suspended' if key.is_suspended else 'Unsuspended'
    log_action(current_user.username, f'{status} key: {key.key}')
    return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash("Can't delete admin account.")
        return redirect(url_for('dashboard'))
    db.session.delete(user)
    db.session.commit()
    log_action(current_user.username, f'Deleted user: {user.username}')
    return redirect(url_for('dashboard'))

@app.route('/api/check_key', methods=['POST'])
def check_key():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'valid': False, 'error': 'No key provided'}), 400

    key = LicenseKey.query.filter_by(key=data['key']).first()
    if not key:
        return jsonify({'valid': False, 'error': 'Key not found'}), 404
    if key.is_suspended:
        return jsonify({'valid': False, 'error': 'Key suspended'}), 403
    if key.expires_at and key.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'error': 'Key expired'}), 403

    return jsonify({'valid': True, 'type': key.type, 'expires_at': str(key.expires_at)})

@app.route('/logs')
@login_required
def logs():
    if current_user.role != 'admin':
        abort(403)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

def create_admin_user():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin', role='admin')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True)
