from flask import Flask, render_template, redirect, url_for, request, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///license_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Constants for roles
ROLE_USER = 'user'
ROLE_ADMIN = 'admin'

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default=ROLE_USER)
    security_question = db.Column(db.String(256), nullable=False)
    security_answer_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    licenses = db.relationship('LicenseKey', backref='owner', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def check_security_answer(self, answer):
        return check_password_hash(self.security_answer_hash, answer.lower().strip())

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False)
    usage_limit = db.Column(db.Integer, default=1)
    usage_count = db.Column(db.Integer, default=0)
    ip_whitelist = db.Column(db.String(256))  # CSV or JSON string for demo

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

# --- USER LOADER ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- FORMS ---

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    email = StringField('Email', validators=[DataRequired(), Length(min=6, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    security_question = SelectField('Security Question', choices=[
        ('pet', 'What was your first pet\'s name?'),
        ('mother_maiden', 'What is your mother\'s maiden name?'),
        ('birth_city', 'In which city were you born?')
    ], validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired(), Length(min=1, max=256)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired()])
    submit = SubmitField('Login')

class LicenseCreateForm(FlaskForm):
    key = StringField('License Key', validators=[DataRequired(), Length(min=5, max=50)])
    user_id = StringField('Assign to User ID (optional)')
    expires_at = StringField('Expiration Date (YYYY-MM-DD, optional)')
    usage_limit = StringField('Usage Limit (optional)')
    submit = SubmitField('Create License')

# --- HELPERS ---

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != ROLE_ADMIN:
            flash("Admin access required", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def log_action(user_id, action, ip_address):
    log = AuditLog(user_id=user_id, action=action, ip_address=ip_address)
    db.session.add(log)
    db.session.commit()

# --- ROUTES ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        hashed_sec_ans = generate_password_hash(form.security_answer.data.lower().strip())
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_pw,
            security_question=form.security_question.data,
            security_answer_hash=hashed_sec_ans,
            role=ROLE_USER
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.check_security_answer(form.security_answer.data):
            login_user(user)
            log_action(user.id, "User logged in", request.remote_addr)
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid login credentials or security answer.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, "User logged out", request.remote_addr)
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    licenses = LicenseKey.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', licenses=licenses)

# ----- ADMIN PANEL -----

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    licenses = LicenseKey.query.all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('admin_panel.html', users=users, licenses=licenses, audit_logs=audit_logs)

@app.route('/admin/create_license', methods=['GET', 'POST'])
@login_required
@admin_required
def create_license():
    form = LicenseCreateForm()
    if form.validate_on_submit():
        user_id = int(form.user_id.data) if form.user_id.data and form.user_id.data.isdigit() else None
        expires_at = None
        if form.expires_at.data:
            try:
                expires_at = datetime.strptime(form.expires_at.data, '%Y-%m-%d')
            except ValueError:
                flash("Expiration date format invalid. Use YYYY-MM-DD.", "warning")
                return render_template('create_license.html', form=form)

        usage_limit = int(form.usage_limit.data) if form.usage_limit.data and form.usage_limit.data.isdigit() else 1

        license_key = LicenseKey(
            key=form.key.data,
            user_id=user_id,
            expires_at=expires_at,
            usage_limit=usage_limit,
            usage_count=0,
            revoked=False
        )
        db.session.add(license_key)
        db.session.commit()
        flash("License key created.", "success")
        log_action(current_user.id, f"Created license {form.key.data}", request.remote_addr)
        return redirect(url_for('admin_panel'))
    return render_template('create_license.html', form=form)

@app.route('/admin/revoke_license/<int:license_id>', methods=['POST'])
@login_required
@admin_required
def revoke_license(license_id):
    license_key = LicenseKey.query.get_or_404(license_id)
    license_key.revoked = True
    db.session.commit()
    flash(f"License {license_key.key} revoked.", "info")
    log_action(current_user.id, f"Revoked license {license_key.key}", request.remote_addr)
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash("You cannot delete yourself.", "warning")
        return redirect(url_for('admin_panel'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted.", "info")
    log_action(current_user.id, f"Deleted user {user.username}", request.remote_addr)
    return redirect(url_for('admin_panel'))

# --- ERROR HANDLERS ---

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# --- RUN APP ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
