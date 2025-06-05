import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

app = Flask(__name__)
app.secret_key = os.getenv('zerixsupersecretcode', 'supersecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=False)  # Store hashed passwords ideally
    role = db.Column(db.String(50), default='User')
    security_question = db.Column(db.String(255), nullable=True)
    security_answer = db.Column(db.String(255), nullable=True)
    last_active = db.Column(db.DateTime, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:  # TODO: Use proper hashing in production
            login_user(user)
            user.last_active = datetime.now(timezone.utc)
            db.session.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# DASHBOARD
@app.route('/dashboard')
@login_required
def dashboard():
    now = datetime.now(timezone.utc)
    last_active = current_user.last_active
    if last_active and (now - last_active).total_seconds() > 600:
        flash('You have been inactive for more than 10 minutes.', 'warning')
    current_user.last_active = now
    db.session.commit()
    return render_template('dashboard.html', user=current_user)

# USERS LIST
@app.route('/users')
@login_required
def users():
    if current_user.role != 'Admin':
        abort(403)
    users = User.query.all()
    return render_template('users.html', users=users)

# SECURITY QUESTION
@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if request.method == 'POST':
        username = request.form.get('username')
        answer = request.form.get('answer')
        user = User.query.filter_by(username=username).first()
        if user and user.security_answer and user.security_answer.lower() == answer.lower():
            # In a real app, redirect to password reset or something
            flash('Security answer correct. You may reset your password.', 'success')
            return redirect(url_for('login'))
        flash('Incorrect security answer.', 'danger')
    return render_template('security_question.html')

# ADMIN PANEL
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'Admin':
        abort(403)
    return render_template('admin.html')

# ADVANCED ADMIN PANEL
@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.role != 'Admin':
        abort(403)
    # Add real features and data for admin here
    return render_template('admin_panel.html')

# CREATE LICENSE (Placeholder route, adapt as needed)
@app.route('/create_license', methods=['GET', 'POST'])
@login_required
def create_license():
    if current_user.role != 'Admin':
        abort(403)
    if request.method == 'POST':
        # Handle license creation logic here
        flash('License created successfully (placeholder)', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('create_license.html')

# 404 ERROR HANDLER
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ADD ADMIN USER (run once manually via browser)
@app.route('/add_admin')
def add_admin():
    # Change these values before running, then remove or comment this route for security
    username = "admin23"
    password = "adminpass1"
    email = "admin@example.com"
    existing = User.query.filter_by(username=username).first()
    if existing:
        return "Admin user already exists."
    new_admin = User(username=username, password=password, email=email, role="Admin")
    db.session.add(new_admin)
    db.session.commit()
    return "Admin user created successfully."

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
