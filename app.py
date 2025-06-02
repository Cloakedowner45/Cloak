from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # CHANGE THIS in production!

# In-memory "database" for demo (replace with real DB later)
users = {
    "Zerixx": {
        "password": "Zerixx$123",
        "role": "admin",
        "id": 1,
        "username": "Zerixx",
    },
}
license_keys = []
audit_logs = []

# Helper to check login
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    for u in users.values():
        if u['id'] == user_id:
            return u
    return None

@app.route('/')
def index():
    user = get_current_user()
    if user:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user['password'] == password:
            session['user_id'] = user['id']
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    return render_template(
        'dashboard.html',
        current_user=user,
        keys=license_keys,
        users=users.values(),
        logs=reversed(audit_logs),  # Show newest first
        show_passwords=False,
    )

@app.route('/generate_key', methods=['POST'])
def generate_key():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    key_type = request.form.get('type')
    if key_type not in ['week', 'month', 'lifetime']:
        flash('Invalid key type.')
        return redirect(url_for('dashboard'))

    key = str(uuid.uuid4())
    created_at = datetime.utcnow()
    expires_at = None
    if key_type == 'week':
        expires_at = created_at + timedelta(weeks=1)
    elif key_type == 'month':
        expires_at = created_at + timedelta(days=30)

    license_keys.append({
        'key': key,
        'type': key_type,
        'created_at': created_at,
        'expires_at': expires_at,
        'id': len(license_keys) + 1,
    })

    audit_logs.append({
        'timestamp': datetime.utcnow(),
        'user_id': user['id'],
        'action': f'Generated {key_type} license key: {key}',
    })
    flash('License key generated.')
    return redirect(url_for('dashboard'))

@app.route('/delete_key/<int:key_id>', methods=['POST'])
def delete_key(key_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    global license_keys
    license_keys = [k for k in license_keys if k['id'] != key_id]
    flash('Key deleted.')
    return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Unauthorized.')
        return redirect(url_for('dashboard'))

    # prevent deleting self
    if user['id'] == user_id:
        flash('Cannot delete yourself.')
        return redirect(url_for('dashboard'))

    global users
    users = {uname: u for uname, u in users.items() if u['id'] != user_id}
    flash('User deleted.')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
