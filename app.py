from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # CHANGE THIS to a secure random key

# Dummy user database (user_id: {password, role, email, security_answer})
users = {
    "admin": {
        "password": "adminpass",
        "role": "admin",
        "email": "admin@example.com",
        "security_answer": "smith"
    },
    "user1": {
        "password": "userpass",
        "role": "user",
        "email": "user1@example.com",
        "security_answer": "johnson"
    },
}

# Simple audit logs: list of dicts with timestamp, user_id, action
logs = []

def log_action(user_id, action):
    logs.insert(0, {"timestamp": datetime.now(), "user_id": user_id, "action": action})
    # keep only last 20 logs
    if len(logs) > 20:
        logs.pop()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id or users.get(user_id, {}).get('role') != 'admin':
            flash("Admin access required.")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = users.get(username)
        if user and user['password'] == password:
            session['user_id'] = username
            flash("Logged in successfully.")
            log_action(username, "Logged in")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    session.clear()
    flash("Logged out successfully.")
    log_action(user_id, "Logged out")
    return redirect(url_for('login'))

@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        answer = request.form.get('answer', '').strip().lower()
        user = users.get(username)
        if user and user['security_answer'].lower() == answer:
            flash(f"Security answer correct. Your password is: {user['password']}")
            log_action(username, "Reset password via security question")
            return redirect(url_for('login'))
        else:
            flash("Incorrect username or security answer.")
    return render_template('security_question.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    user_role = users[user_id]['role']
    return render_template('admin.html', current_user={'id': user_id}, users=users, logs=logs)

@app.route('/users')
@login_required
@admin_required
def all_users():
    return render_template('users.html', users=users)

@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    current_user_id = session.get('user_id')
    if user_id == current_user_id:
        flash("You cannot delete yourself.")
        return redirect(url_for('dashboard'))

    if user_id in users:
        users.pop(user_id)
        flash(f"User {user_id} deleted.")
        log_action(current_user_id, f"Deleted user {user_id}")
    else:
        flash("User not found.")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
