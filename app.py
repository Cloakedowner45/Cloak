from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Dummy user setup for this example
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

users = {
    "admin": User(id=1, username="admin", password_hash="pbkdf2:sha256:600000$xyz...")  # Replace with your hashed password
}

@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if str(user.id) == str(user_id):
            return user
    return None

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = users.get(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    keys = []  # Replace with actual license key query
    users_list = []  # Replace with actual user query
    logs = []  # Replace with actual audit log query
    show_passwords = session.get("pin_verified", False)
    return render_template("dashboard.html", keys=keys, users=users_list, logs=logs, show_passwords=show_passwords, current_user=current_user)

@app.route("/verify_pin", methods=["POST"])
@login_required
def verify_pin():
    entered_pin = request.form.get("pin")
    correct_pin = "1234"  # Replace with your secure PIN

    if entered_pin == correct_pin:
        session["pin_verified"] = True
        flash("PIN verified successfully. Passwords are now visible.", "success")
    else:
        flash("Invalid PIN. Please try again.", "danger")
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
