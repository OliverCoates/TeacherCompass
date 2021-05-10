#Teacher Compass
#https://realpython.com/flask-google-login/
#OliverCoates
#17012@burnside.school.nz

import json
import os
#Install packages:

print("Installing packages...")
os.system("pip install -r requirements.txt -q")

import sqlalchemy

from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, abort
from flask import render_template, redirect, request, url_for, flash
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
    UserMixin
)
from oauthlib.oauth2 import WebApplicationClient
import requests

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

#Internal Imports
#from db import init_db_command
#from user import User

# Configuration
from credentials import GOOGLE_CLIENT_SECRET, GOOGLE_CLIENT_ID, SECRET_KEY
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String, nullable = False)
    email = db.Column(db.String, nullable = False)
    profile_pic = db.Column(db.String)

    score = db.relationship("Score", backref="user")

class Score(db.Model):
    __tablename__ = 'score'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    teacher_code = db.Column(db.String, nullable = False)
    scoreX = db.Column(db.Integer)
    scoreY = db.Column(db.Integer)
    scoreZ = db.Column(db.Integer)

class Teachers(db.Model):
    __tablename__ = 'teacher'
    id = db.Column(db.Integer, primary_key=True)
    teacher_code = db.Column(db.String, nullable = False)
    valueX = db.Column(db.Integer)
    valueY = db.Column(db.Integer)
    valueZ = db.Column(db.Integer)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

#Add error handling?
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

#Redirect to home page
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"], )

    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        flash('Error: User email not available or not verified by Google', 'error')
        return redirect('/home')

    #print(" ------> ", users_email.split('@'))
    if users_email.split('@')[1] == "burnside.school.nz":
        user = User.query.get(unique_id)
        if not user:
            user = User(id=unique_id, name=users_name, email=users_email, profile_pic=picture)
            db.session.add(user)
            db.session.commit()

        login_user(user)
    else:
        flash('Non-Burnside accounts are not allowed', 'error')
    return redirect('/')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/score', methods=["GET","POST"])
def user():
    #Get all the teacher code from the database
    # teachers = Teachers.query.all(teacher_code)
    teachers = [teacher.teacher_code for teacher in Teachers.query.all()]
    #teachers = Teachers.query.with_entities(Teachers.teacher_code).scaler().all()
    print(">>> ", teachers)

    if current_user.is_authenticated:
        print("The user is authenticated")
    else:
        return redirect("/home")

    if request.method == "POST":
        try:
            submittedX = int(request.form.get("xInput"))
            submittedY = int(request.form.get("yInput"))
            submittedZ = int(request.form.get("zInput"))
        except ValueError:
            flash("That is not a number", "info")
        else:
            if (-10 <= submittedX <= 10) and (-10 <= submittedY <= 10) and (-10 <= submittedZ <= 10):
                teacher_code = request.form.get("TeacherCode")
                print("Received values - X:",submittedX," Y:", submittedY," Z:", submittedZ)
                print("Teacher code ", teacher_code)
                print("User: ", current_user.name, " | ID: ", current_user.id)

                # Check if score has allready been submitted by this user
                responseMessage = ""
                score = Score.query.filter_by(
                    teacher_code = teacher_code,
                    user         = current_user).first()
                if score is None:
                    responseMessage = "Your values were submitted sucessfully"
                    score = Score()
                else:
                    responseMessage = "Your values were updated sucessfully"
                score.user = current_user
                score.teacher_code = teacher_code
                score.scoreX = submittedX
                score.scoreY = submittedY
                score.scoreZ = submittedZ
                print("Submitting score")
                db.session.add(score)
                db.session.commit()
                flash(responseMessage, 'info')
            else:
                flash("Number not within valid range", "info")
        return redirect('/score')
        #current_user.score
    return render_template('score.html', teachers = teachers)

@app.route('/api/score/<string:teacher_code>')
def api_score(teacher_code):
    if not current_user.is_authenticated:
        abort(401)
    score = Score.query.filter_by(user=current_user, teacher_code=teacher_code).first()
    if score is None:
        return jsonify({
            "x": 0,
            "y": 0,
            "z": 0
        })
    return jsonify({
        "x": score.scoreX,
        "y": score.scoreY,
        "z": score.scoreZ
    })

db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
