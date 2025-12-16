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


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    response = make_response(redirect("/login.html?error=Please log in again"))
    response.delete_cookie("access_token_cookie")
    return response


@jwt.invalid_token_loader
def invalid_token_callback(error):
    response = make_response(redirect("/login.html?error=Please log in again"))
    response.delete_cookie("access_token_cookie")
    return response


@jwt.unauthorized_loader
def unauthorized_callback(error):
    return redirect("/login.html?error=Please log in")


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
            # Check if user has 2FA enabled
            totp_data = dbHandler.getUserTOTP(email)
            if totp_data and totp_data["tfa_enabled"]:
                # 2FA is enabled, proceed to verification
                session["pending_2fa_email"] = email
                session["pending_2fa_name"] = user_data["name"]
                return redirect("/verify_tfa.html")
            else:
                # 2FA not enabled - redirect to setup (mandatory)
                session["pending_2fa_email"] = email
                session["pending_2fa_name"] = user_data["name"]
                return redirect("/setup_2fa.html?mandatory=true")
        else:
            error = "Incorrect username or password"
            return render_template("/login.html", error=error)
    error = request.args.get("error")
    return render_template("/login.html", error=error)


@app.route("/verify_tfa.html", methods=["GET", "POST"])
def verify_tfa():
    if "pending_2fa_email" not in session:
        return redirect("/login.html")
    if request.method == "POST":
        otp_input = request.form["otp"]
        email = session["pending_2fa_email"]
        name = session["pending_2fa_name"]
        totp_data = dbHandler.getUserTOTP(email)
        if totp_data and totp_data["totp_secret"]:
            totp = pyotp.TOTP(totp_data["totp_secret"])
            if totp.verify(otp_input, valid_window=1):
                # Clear session data
                session.pop("pending_2fa_email", None)
                session.pop("pending_2fa_name", None)
                # Create JWT and login
                access_token = create_access_token(
                    identity=str(email),
                    additional_claims={"email": email, "name": name},
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
                error = "Invalid OTP code"
                return render_template("/verify_tfa.html", error=error)
    return render_template("/verify_tfa.html")


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
    order_by = request.args.get("order_by", "created")
    order_dir = request.args.get("order_dir", "DESC")
    filter_author = request.args.get("filter_author", "")
    filter_project = request.args.get("filter_project", "")
    filter_date = request.args.get("filter_date", "")
    entries = dbHandler.getLogs(
        order_by=order_by,
        order_dir=order_dir,
        filter_author=filter_author if filter_author else None,
        filter_project=filter_project if filter_project else None,
        filter_date=filter_date if filter_date else None,
    )
    for entry in entries:
        if isinstance(entry["created"], str):
            entry["created"] = datetime.strptime(entry["created"], "%Y-%m-%d %H:%M:%S")
        if isinstance(entry["starttime"], str):
            entry["starttime"] = datetime.strptime(entry["starttime"], "%Y-%m-%dT%H:%M")
        if isinstance(entry["endtime"], str):
            entry["endtime"] = datetime.strptime(entry["endtime"], "%Y-%m-%dT%H:%M")
    return render_template(
        "/loghome.html",
        entries=entries,
        order_by=order_by,
        order_dir=order_dir,
        filter_author=filter_author,
        filter_project=filter_project,
        filter_date=filter_date,
    )


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
@jwt_required()
def logoutpage():
    return render_template("/logout.html")


@app.route("/logout", methods=["GET"])
@jwt_required()
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("access_token_cookie")
    app_log.info("User logged out")
    return response


@app.route("/log/<int:log_id>")
@jwt_required()
def view_log(log_id):
    entry = dbHandler.getLog(log_id)
    if entry:
        if isinstance(entry["created"], str):
            entry["created"] = datetime.strptime(entry["created"], "%Y-%m-%d %H:%M:%S")
        if isinstance(entry["starttime"], str):
            entry["starttime"] = datetime.strptime(entry["starttime"], "%Y-%m-%dT%H:%M")
        if isinstance(entry["endtime"], str):
            entry["endtime"] = datetime.strptime(entry["endtime"], "%Y-%m-%dT%H:%M")
        return render_template("logdetail.html", entry=entry)
    else:
        return "Log not found", 404


@app.route("/logdetail/<int:log_id>", methods=["GET", "POST"])
@jwt_required()
def editlog(log_id):
    user_id = get_jwt_identity()
    if request.method == "POST":
        id = log_id
        project = request.form["project"]
        starttime = request.form["date_started"]
        endtime = request.form["date_finished"]
        message = request.form["message"]
        editlog = dbHandler.editLog(id, project, starttime, endtime, message)
        if editlog:
            return redirect("/loghome.html")
        else:
            # Get fresh entry from database to re-populate form
            entry = dbHandler.getLog(log_id)
            if entry:
                # Format datetime fields for datetime-local input
                if isinstance(entry["starttime"], str):
                    entry["starttime"] = datetime.strptime(
                        entry["starttime"], "%Y-%m-%dT%H:%M"
                    ).strftime("%Y-%m-%dT%H:%M")
                else:
                    entry["starttime"] = entry["starttime"].strftime("%Y-%m-%dT%H:%M")
                if isinstance(entry["endtime"], str):
                    entry["endtime"] = datetime.strptime(
                        entry["endtime"], "%Y-%m-%dT%H:%M"
                    ).strftime("%Y-%m-%dT%H:%M")
                else:
                    entry["endtime"] = entry["endtime"].strftime("%Y-%m-%dT%H:%M")
            return render_template("/editlog.html", error=True, entry=entry)
    entry = dbHandler.getLog(log_id)
    if not entry:
        return render_template("/editlog.html", error=True, entry=None)
    if isinstance(entry["starttime"], str):
        entry["starttime"] = datetime.strptime(
            entry["starttime"], "%Y-%m-%dT%H:%M"
        ).strftime("%Y-%m-%dT%H:%M")
    else:
        entry["starttime"] = entry["starttime"].strftime("%Y-%m-%dT%H:%M")
    if isinstance(entry["endtime"], str):
        entry["endtime"] = datetime.strptime(
            entry["endtime"], "%Y-%m-%dT%H:%M"
        ).strftime("%Y-%m-%dT%H:%M")
    else:
        entry["endtime"] = entry["endtime"].strftime("%Y-%m-%dT%H:%M")
    return render_template("/editlog.html", entry=entry)


@app.route("/setup_2fa.html", methods=["GET", "POST"])
def setup_2fa():
    # Check if this is mandatory setup or logged-in user
    mandatory = request.args.get("mandatory") == "true"

    if mandatory:
        # User must set up 2FA before logging in
        if "pending_2fa_email" not in session:
            return redirect("/login.html")
        email = session["pending_2fa_email"]
        name = session["pending_2fa_name"]
    else:
        # This shouldn't happen anymore, but keep for safety
        return redirect("/loghome.html")

    if request.method == "POST":
        otp_input = request.form["otp"]
        user_secret = session.get("temp_totp_secret")

        if user_secret:
            totp = pyotp.TOTP(user_secret)
            if totp.verify(otp_input, valid_window=1):
                # Save the secret to database
                if dbHandler.updateUserTOTP(email, user_secret):
                    session.pop("temp_totp_secret", None)
                    session.pop("temp_qr_code", None)
                    session.pop("pending_2fa_email", None)
                    session.pop("pending_2fa_name", None)
                    app_log.info(f"2FA enabled for user: {email}")

                    # Create JWT and login automatically
                    access_token = create_access_token(
                        identity=str(email),
                        additional_claims={"email": email, "name": name},
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
                    error = "Failed to enable 2FA"
                    return render_template(
                        "/setup_tfa.html",
                        error=error,
                        qr_code=session.get("temp_qr_code"),
                        mandatory=True,
                    )
            else:
                error = "Invalid OTP code. Please try again."
                return render_template(
                    "/setup_tfa.html",
                    error=error,
                    qr_code=session.get("temp_qr_code"),
                    mandatory=True,
                )

    # Generate new secret
    user_secret = pyotp.random_base32()
    totp = pyotp.TOTP(user_secret)
    otp_uri = totp.provisioning_uri(name=email, issuer_name="Devlog App")
    qr_code = pyqrcode.create(otp_uri)
    stream = BytesIO()
    qr_code.png(stream, scale=5)
    qr_code_b64 = base64.b64encode(stream.getvalue()).decode("utf-8")

    # Store temporarily in session
    session["temp_totp_secret"] = user_secret
    session["temp_qr_code"] = qr_code_b64

    return render_template("/setup_tfa.html", qr_code=qr_code_b64, mandatory=True)


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
