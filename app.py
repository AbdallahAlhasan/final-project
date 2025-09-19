from flask import Flask, render_template, request, redirect, url_for, flash, session
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
# 🔹 Use a more secure secret key. It's better to generate this dynamically in production.
# For example: import os; app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
app.secret_key = "d010c710c551717f91a5e171b3e895471c6d3d467773f32c0211f422e1189c47"

# 🔹 CS50 SQL database
db = SQL("sqlite:///users.db")

# 🔹 Create table if it doesn't exist
db.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

# 🔹 Validate email format (must be like user@domain.com)
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

# 🔹 Validate password strength
def is_strong_password(password):
    """
    Strong password rules:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    # Added more common special characters to the pattern
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False
    return True

# 🏠 Home page
@app.route("/")
def home():
    return render_template("home.html", title="Home")

# 🔑 Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username_or_email", "").strip()
        password = request.form.get("password", "").strip()

        if not username_or_email or not password:
            flash("Please enter both username/email and password", "danger")
            return redirect(url_for("login"))

        user = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", username_or_email, username_or_email)

        if user and check_password_hash(user[0]["password"], password):
            session["username"] = user[0]["username"]
            flash("Logged in successfully!", "success")
            return redirect(url_for("calculator"))
        else:
            flash("Invalid username/email or password", "danger")

    return render_template("login.html", title="Login")

# 📝 Register page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # 🔹 Check all fields
        if not username or not email or not password:
            flash("Please fill out all fields", "warning")
            return redirect(url_for("register"))

        # 🔹 Check email validity
        if not is_valid_email(email):
            flash("Please enter a valid email (e.g., user@domain.com)", "danger")
            return redirect(url_for("register"))

        # 🔹 Check password strength
        if not is_strong_password(password):
            flash("Password must be at least 8 characters and include uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for("register"))
        
        # 🔹 Security improvement: Check if username or email already exists before inserting
        existing_user = db.execute("SELECT id FROM users WHERE username = ? OR email = ?", username, email)
        if existing_user:
            flash("Username or email already exists", "danger")
            return redirect(url_for("register"))

        # 🔹 Hash password
        hashed_password = generate_password_hash(password)

        try:
            db.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                username, email, hashed_password
            )
            flash("Account created successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            # 🔹 Catch and handle more specific database errors if needed, though the pre-check above mitigates this.
            print(f"Database error during registration: {e}")
            flash("An unexpected error occurred. Please try again later.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html", title="Register")

# 📊 Calculator page
@app.route("/calculator")
def calculator():
    return render_template("calculator.html", title="Calculator")


# 🚪 Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("You have been logged out", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)