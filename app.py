from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')
    email = db.Column(db.String(150), nullable=True)
    security_question = db.Column(db.String(255), nullable=True)
    security_answer = db.Column(db.String(255), nullable=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['user_id'] = user.id
            session['last_active'] = datetime.now(timezone.utc)
            login_user(user)
            return redirect(url_for('security_question'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/security-question', methods=['GET', 'POST'])
@login_required
def security_question():
    user = current_user

    if request.method == 'POST':
        answer = request.form['answer'].strip().lower()
        if user.security_answer.strip().lower() == answer:
            session['last_active'] = datetime.now(timezone.utc)
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect answer.')

    return render_template('security_question.html', question=user.security_question)

@app.route('/dashboard')
@login_required
def dashboard():
    last_active = session.get('last_active')
    now = datetime.now(timezone.utc)
    if last_active and (now - last_active).total_seconds() > 600:
        logout_user()
        flash('⏰ Session expired. Please log in again.')
        return redirect(url_for('login'))

    session['last_active'] = now
    return render_template('dashboard.html', role=current_user.role)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    users = User.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted.')
    return redirect(url_for('admin'))

@app.route('/users')
@login_required
def all_users():
    users = User.query.all()
    return render_template('users.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
