from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db.init_app(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

with app.app_context():
    db.create_all()

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("home.html")

# ---------------- SIGNUP (HTML) ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("User already exists", "error")
            return redirect(url_for("signup"))

        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        token = serializer.dumps(email, salt="email-verify")
        print(f"Verify link: http://localhost:5000/verify/{token}")

        flash("Signup successful! Check terminal for verification link.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

# ---------------- VERIFY EMAIL ----------------
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt="email-verify", max_age=3600)
    except:
        return "Verification link expired, invalid, or already used."

    user = User.query.filter_by(email=email).first()
    if not user:
        return "User not found."

    if user.is_verified:
        return "Email already verified! You can now login."

    user.is_verified = True
    db.session.commit()
    return "Email verified successfully! You can now login."

# ---------------- LOGIN (HTML) ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials", "error")
            return redirect(url_for("login"))

        if not user.is_verified:
            flash("Email not verified", "error")
            return redirect(url_for("login"))

        flash("Login successful!", "success")
        return "Welcome! (Next: dashboard)"

    return render_template("login.html")


# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
def admin_dashboard():
    # In real apps, you'd require login + role check
    with app.app_context():
        users = User.query.all()
    return render_template("admin.html", users=users)


# ---------------- DELETE UNVERIFIED USER ----------------
@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            return "User not found", 404

        if user.is_verified:
            return "Cannot delete verified user!", 403

        db.session.delete(user)
        db.session.commit()
        return redirect("/admin")

# ---------------- VERIFY USER (ADMIN) ----------------
@app.route("/admin/verify/<int:user_id>", methods=["POST"])
def admin_verify_user(user_id):
    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            return "User not found", 404

        if user.is_verified:
            return "User is already verified!", 400

        user.is_verified = True
        db.session.commit()
        return redirect("/admin")


if __name__ == "__main__":
    app.run(debug=True)


