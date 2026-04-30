from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import pyotp
import qrcode
import jwt
import datetime
import os

app = Flask(__name__)
app.secret_key = "secret123"

# ---------------- DB ----------------
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password BLOB,
        role TEXT,
        secret TEXT
    )''')

    conn.commit()
    conn.close()

init_db()

# ---------------- REGISTER ----------------
@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        if not name or not email or not password or not role:
            return "All fields are required!"

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        secret = pyotp.random_base32()

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        try:
            c.execute("INSERT INTO users (name,email,password,role,secret) VALUES (?,?,?,?,?)",
                      (name, email, hashed, role, secret))
            user_id = c.lastrowid
            conn.commit()
        except:
            conn.close()
            return "Email already exists!"

        conn.close()

        session["user_id"] = user_id

        if not os.path.exists("static"):
            os.makedirs("static")

        filename = f"static/qr_{user_id}.png"

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(email, issuer_name="AuthSystem")

        img = qrcode.make(uri)
        img.save(filename)

        return render_template("verify.html", qr=filename)

    return render_template("register.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            return "Missing email or password"

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user[3]):
            session["user_id"] = user[0]
            return redirect("/verify")
        else:
            return "Invalid login"

    return render_template("login.html")


# ---------------- 2FA ----------------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],))
    user = c.fetchone()
    conn.close()

    if request.method == "POST":

        code = request.form.get("code")

        if not code:
            return "Enter 2FA code"

        totp = pyotp.TOTP(user[5])

        if totp.verify(code, valid_window=1):
            token = jwt.encode({
                "user_id": user[0],
                "name": user[1],
                "email": user[2],
                "role": user[4],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, "secretkey", algorithm="HS256")

            session["token"] = token
            return redirect("/dashboard")
        else:
            return "Invalid 2FA code"

    qr_file = f"static/qr_{user[0]}.png"
    if not os.path.exists(qr_file):
        totp = pyotp.TOTP(user[5])
        uri = totp.provisioning_uri(user[2], issuer_name="AuthSystem")
        img = qrcode.make(uri)
        img.save(qr_file)

    return render_template("verify.html", qr=qr_file)


# ---------------- TOKEN CHECK ----------------
def check_token():
    if "token" not in session:
        return None
    try:
        data = jwt.decode(session["token"], "secretkey", algorithms=["HS256"])
        return data
    except:
        return None


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    user = check_token()
    if not user:
        return redirect("/login")

    return render_template("dashboard.html", role=user["role"] , token=session["token"])


@app.route("/profile")
def profile():
    user = check_token()
    if not user:
        return redirect("/login")

    return render_template("profile.html", user=user)
# ---------------- ROLE ROUTES ----------------
@app.route("/admin")
def admin():
    user = check_token()
    if not user or user["role"] != "Admin":
        return "Access Denied"
    return render_template("admin.html")


@app.route("/manager")
def manager():
    user = check_token()
    if not user or user["role"] != "Manager":
        return "Access Denied"
    return render_template("manager.html")


@app.route("/user")
def user_page():
    user = check_token()
    if not user or user["role"] != "User":
        return "Access Denied"
    return render_template("user.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)