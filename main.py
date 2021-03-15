#Teacher Compass
#https://realpython.com/flask-google-login/

import json
import os
import sqlalchemy

from flask import Flask
from flask import render_template, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

#Internal Imports
#from db import init_db_command
#from user import User

# Configuration
from credentials import GOOGLE_CLIENT_SECRET, GOOGLE_CLIENT_ID, SECRET_KEY
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

app = Flask(__name__)
app.secret_key = SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(app)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

#Redirect to home page
@app.route('/')
def index():
    return redirect("/home")

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/user')
def user():
    return render_template('user.html')

if __name__ == '__main__':
    app.run(debug=True)
