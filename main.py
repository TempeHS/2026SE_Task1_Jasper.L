from flask import Flask, render_template, request, redirect, url_for, session
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging
import pyotp
import pyqrcode
import os
import base64
from io import BytesIO

import userManagement as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Generate a unique basic 16 key: https://acte.ltd/utils/randomkeygen
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
csrf = CSRFProtect(app)


# Redirect index.html to domain root for consistent UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
        "base-uri": "'self'",
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self'",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
    }
)
def index():
    return render_template("/index.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


@app.route("/login.html", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user_valid = dbHandler.getUser(email, password)
        if user_valid:
            return render_template("/tfa.html")
        else:
            error = "Incorrect username or password"
            return render_template("/login.html", error=error)
    else:
        return render_template("/login.html")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        emailsubmit = dbHandler.newUser(email, password)
        if emailsubmit:
            return render_template("/login.html")
        else:
            error = "Email is already in use"
            return render_template("/signup.html", error=error)
    else:
        return render_template("/signup.html")


# @app.route("/tfa.html", methods=["POST", "GET"])
# def home():
#     user_secret = pyotp.random_base32()
#     totp = pyotp.TOTP(user_secret)
#     totp = pyotp.TOTP(user_secret)
#     otp_uri = totp.provisioning_uri(name=username, issuer_name="Devlog App")
#     qr_code = pyqrcode.create(otp_uri)
#     stream = BytesIO()
#     qr_code.png(stream, scale=5)
#     qr_code_b64 = base64.b64encode(stream.getvalue()).decode("utf-8")
#     if request.method == "POST":
#         otp_input = request.form["otp"]
#         if totp.verify(otp_input):
#             return render_template("/loghome.html")
#         else:
#             return "Invalid OTP. Please try again.", 401
#     return render_template("/tfa.html")


# example CSRF protected form
@app.route("/form.html", methods=["POST", "GET"])
def form():
    if request.method == "POST":
        email = request.form["email"]
        text = request.form["text"]
        return render_template("/form.html")
    else:
        return render_template("/form.html")


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
