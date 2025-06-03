from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from datetime import datetime, timedelta
import logging

app = Flask(__name__)
app.secret_key = 'zerixxsecret1$'  # Change this to a strong secret key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- User and role data ---
class User(UserMixin):
    def __init__(self, id, role='user'):
        self.id = id
        self.role = role

users = {
    "Zerixx": {
        "password": "Zerixxpass",
        "role": "admin",
        "security_question": "Your pet's name?",
        "security_answer": "fluffy"
    },
    "User1": {
        "password": "User1pass",
        "role": "user",
        "security_question": "Favorite color?",
        "security_answer": "blue"
    }
}

# --- Login attempt tracking ---
login_attempts = {}
LOCKOUT_TIME = timedelta(minutes=5)
MAX_ATTEMPTS = 5

# --- Login analytics ---
logging.basicConfig(filename='login_analytics.log', level=logging.INFO, 
                    format='%(asctime)s %(message)s')

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        role = users[user_id].get('role', 'user')
        return User(user_id, role)
    return None

def is_locked_out(username):
    record = login_attempts.get(username)
    if record:
        attempts, last_time, locked_until = record
        if locked_until and datetime.now() < locked_until:
            return True, (locked_until - datetime.now()).seconds
    return False, 0

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)

        locked, seconds_left = is_locked_out(username)
        if locked:
            flash(f'⚠️ Account locked due to multiple failed attempts. Try again in {seconds_left} seconds.')
            return redirect(url_for('login'))

        if user and user['password'] == password:
            # Reset login attempts
            login_attempts.pop(username, None)
            user_obj = User(username, user.get('role', 'user'))
            login_user(user_obj)

            # Set trusted device cookie (expires in 30 days)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('device_id', f"{username}_trusted", max_age=60*60*24*30)

            ip = request.remote_addr
            logging.info(f"SUCCESS login for {username} from IP {ip}")

            return resp
        else:
            # Failed attempt tracking
            now = datetime.now()
            attempts, last_time, locked_until = login_attempts.get(username, (0, None, None))
            if last_time and now - last_time > LOCKOUT_TIME:
                attempts = 0  # Reset after lockout period

            attempts += 1
            if attempts >= MAX_ATTEMPTS:
                locked_until = now + LOCKOUT_TIME
                flash('⚠️ Too many failed attempts. Your account is locked for 5 minutes.')
                logging.info(f"LOCKOUT triggered for {username}")
            else:
                locked_until = None
                flash('❌ Invalid username or password')

            login_attempts[username] = (attempts, now, locked_until)

            ip = request.remote_addr
            logging.info(f"FAILED login attempt {attempts} for {username} from IP {ip}")

            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('show_passwords', None)
    flash("👋 You've been logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    # Session timeout: 10 minutes inactivity
    last_active = session.get('last_active')
    now = datetime.now()
    if last_active and (now - last_active).total_seconds() > 600:
        logout_user()
        flash('⏰ Session expired due to inactivity. Please log in again.')
        return redirect(url_for('login'))

    session['last_active'] = now

    show_passwords = session.get('show_passwords', False)
    trusted_device = request.cookies.get('device_id') == f"{current_user.id}_trusted"

    # Role-based dashboard: Could redirect to different pages if needed
    return render_template('dashboard.html',
                           show_passwords=show_passwords,
                           role=current_user.role,
                           trusted_device=trusted_device)

@app.route('/verify_pin', methods=['POST'])
@login_required
def verify_pin():
    pin = request.form.get('pin')
    correct_pin = "9909"  # Replace with secure PIN validation

    if pin == correct_pin:
        session['show_passwords'] = True
        flash('🔑 PIN verified! Passwords are now visible.')
    else:
        session['show_passwords'] = False
        flash('❌ Incorrect PIN. Please try again.')

    return redirect(url_for('dashboard'))

@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if request.method == 'POST':
        username = request.form.get('username')
        answer = request.form.get('answer', '').lower()
        user = users.get(username)

        if user and user['security_answer'].lower() == answer:
            flash('✅ Security question passed! Password reset options coming soon.')
            # TODO: Add password reset flow or email link here
        else:
            flash('❌ Wrong answer to the security question.')

    question = ''
    if request.args.get('username'):
        question = users.get(request.args.get('username'), {}).get('security_question', '')

    return render_template('security_question.html', question=question)

# Placeholder for admin key suspension - implement your logic here
@app.route('/admin/suspend_key/<key_id>', methods=['POST'])
@login_required
def suspend_key(key_id):
    if current_user.role != 'admin':
        flash("❌ Unauthorized access.")
        return redirect(url_for('dashboard'))

    # TODO: Add suspension logic here (e.g., update DB to mark key as suspended)
    flash(f"🔒 License key {key_id} suspended successfully.")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
