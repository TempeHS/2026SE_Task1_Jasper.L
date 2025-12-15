from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    make_response,
)
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import tempfile
import logging
import pyotp
import pyqrcode
import os
import base64
from io import BytesIO
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from datetime import datetime

import DB_Handler as dbHandler

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
app.config["JWT_SECRET_KEY"] = app.secret_key
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config["DATABASE"] = "databaseFiles/database.db"
csrf = CSRFProtect(app)
jwt = JWTManager(app)

app.teardown_appcontext(dbHandler.close_db)


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
        user_data = dbHandler.getUser(email, password)
        if user_data:
            access_token = create_access_token(
                identity=str(email),
                additional_claims={"email": email, "name": user_data["name"]},
            )
            response = make_response(redirect("/loghome.html"))
            response.set_cookie(
                "access_token_cookie",
                access_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=3600,
            )
            return response
        else:
            error = "Incorrect username or password"
            return render_template("/login.html", error=error)
    return render_template("/login.html")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        name = request.form["name"]
        emailsubmit = dbHandler.newUser(name, email, password)
        if emailsubmit:
            return redirect("/login.html")
        else:
            error = "Email is already in use"
            return render_template("/signup.html", error=error)

    return render_template("/signup.html")


@app.route("/loghome.html", methods=["GET"])
@jwt_required()
def loghome():
    user_id = get_jwt_identity()
    entries = dbHandler.getLogs()
    for entry in entries:
        if isinstance(entry["created"], str):
            entry["created"] = datetime.strptime(entry["created"], "%Y-%m-%d %H:%M:%S")
        if isinstance(entry["starttime"], str):
            entry["starttime"] = datetime.strptime(entry["starttime"], "%Y-%m-%dT%H:%M")
        if isinstance(entry["endtime"], str):
            entry["endtime"] = datetime.strptime(entry["endtime"], "%Y-%m-%dT%H:%M")
    return render_template("/loghome.html", entries=entries)


@app.route("/createlog.html", methods=["GET", "POST"])
@jwt_required()
def createlog():
    user_id = get_jwt_identity()
    if request.method == "POST":
        project = request.form["project"]
        starttime = request.form["date_started"]
        endtime = request.form["date_finished"]
        message = request.form["message"]
        claims = get_jwt()
        author = claims.get("name")
        createlog = dbHandler.createLog(project, author, starttime, endtime, message)
        if createlog:
            return redirect("loghome.html")
        else:
            return render_template("/createlog.html", error=True)
    return render_template("/createlog.html")


@app.route("/logout.html", methods=["GET"])
def logoutpage():
    return render_template("/logout.html")


@app.route("/logout", methods=["GET"])
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("access_token_cookie")
    app_log.info("User logged out")
    return response


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
