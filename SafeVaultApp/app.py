from flask import Flask, render_template, request, redirect, session
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "safevault_secret"

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

def sanitize_input(input_str):
    return re.sub(r'[<>"\'%;()&+]', '', input_str)

@app.route("/")
def index():
    return render_template("webform.html")

@app.route("/submit", methods=["POST"])
def submit():
    username = sanitize_input(request.form["username"])
    email = sanitize_input(request.form["email"])
    password = generate_password_hash(request.form["password"])

    cursor.execute("INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (?, ?, ?, ?)", (username, email, password, "user"))
    conn.commit()
    return "User registered successfully."

@app.route("/login", methods=["POST"])
def login():
    username = sanitize_input(request.form["username"])
    password = request.form["password"]

    cursor.execute("SELECT PasswordHash, Role FROM Users WHERE Username = ?", (username,))
    result = cursor.fetchone()
    if result and check_password_hash(result[0], password):
        session["username"] = username
        session["role"] = result[1]
        return redirect("/dashboard")
    return "Login failed"

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return "Access Denied"
    return "Welcome Admin"

@app.route("/dashboard")
def dashboard():
    return f"Welcome {session.get('username')}"

if __name__ == "__main__":
    app.run(debug=True)