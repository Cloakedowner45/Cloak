from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

app = Flask(__name__)
app.secret_key = 'zerixxsecret1$'  # Change this to a strong secret key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user class and user store
class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = {
    "Zerixx": {"password": "Zerixxpass"}
}

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)

        if user and user['password'] == password:
            user_obj = User(username)
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('show_passwords', None)
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    show_passwords = session.get('show_passwords', False)
    return render_template('dashboard.html', show_passwords=show_passwords)

@app.route('/verify_pin', methods=['POST'])
@login_required
def verify_pin():
    pin = request.form.get('pin')
    correct_pin = "9909"  # Change this to your actual PIN logic or secure check

    if pin == correct_pin:
        session['show_passwords'] = True
        flash('PIN verified! Passwords are now visible.')
    else:
        flash('Incorrect PIN. Please try again.')
        session['show_passwords'] = False

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
