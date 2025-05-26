from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_this_to_a_random_secret'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keys.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # Plaintext for demo only!

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(32), unique=True, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # week, month, lifetime
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    keys = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template('dashboard.html', keys=keys, users=users)

@app.route('/generate_key', methods=['POST'])
@login_required
def generate_key():
    key_type = request.form.get('type')
    if key_type not in ['week', 'month', 'lifetime']:
        flash('Invalid key type selected')
        return redirect(url_for('dashboard'))

    new_key = secrets.token_hex(8)  # 16 chars hex key

    if key_type == 'week':
        expires = datetime.utcnow() + timedelta(weeks=1)
    elif key_type == 'month':
        expires = datetime.utcnow() + timedelta(days=30)
    else:
        expires = None

    license_key = LicenseKey(key=new_key, type=key_type, expires_at=expires)
    db.session.add(license_key)
    db.session.commit()
    flash(f'New {key_type} key generated: {new_key}')
    return redirect(url_for('dashboard'))

@app.route('/delete_key/<int:key_id>', methods=['POST'])
@login_required
def delete_key(key_id):
    license_key = LicenseKey.query.get(key_id)
    if not license_key:
        abort(404)
    db.session.delete(license_key)
    db.session.commit()
    flash('License key deleted successfully.')
    return redirect(url_for('dashboard'))

# New route to delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Prevent deleting yourself
    if current_user.id == user_id:
        flash("You cannot delete yourself!")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if not user:
        abort(404)

    # Optionally prevent deleting admin user, or add your own logic here
    if user.username.lower() == 'admin':
        flash("Cannot delete the admin user.")
        return redirect(url_for('dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/api/check_key', methods=['POST'])
def check_key():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'valid': False, 'error': 'No key provided'}), 400

    key = data['key']
    license_key = LicenseKey.query.filter_by(key=key).first()

    if not license_key:
        return jsonify({'valid': False, 'error': 'Key not found'}), 404

    if license_key.expires_at and license_key.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'error': 'Key expired'}), 403

    return jsonify({'valid': True, 'type': license_key.type, 'expires_at': str(license_key.expires_at)})

@app.route('/api/validate', methods=['GET'])
def validate_key():
    key = request.args.get('key')
    if not key:
        return jsonify({'success': False, 'error': 'No key provided'}), 400

    license_key = LicenseKey.query.filter_by(key=key).first()
    if not license_key:
        return jsonify({'success': False, 'error': 'Key not found'}), 404

    if license_key.expires_at and license_key.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'error': 'Key expired'}), 403

    return jsonify({'success': True, 'type': license_key.type, 'expires_at': str(license_key.expires_at)})

def create_admin_user():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin')  # CHANGE after first login!
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True)
