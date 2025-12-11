from flask import Flask, render_template, request, redirect, url_for, session
import pyotp
import pyqrcode
import os
import base64
from io import BytesIO
import userManagement as dbHandler

app = Flask(__name__)
app.secret_key = "my_secret_key"


def home():
    user_secret = pyotp.random_base32()
    totp = pyotp.TOTP(user_secret)
    totp = pyotp.TOTP(user_secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name="YourAppName")
    qr_code = pyqrcode.create(otp_uri)
    stream = BytesIO()
    qr_code.png(stream, scale=5)
    qr_code_b64 = base64.b64encode(stream.getvalue()).decode("utf-8")
