from flask import Flask, abort, render_template, request, redirect, session
from flask_pymongo import PyMongo
from hashlib import sha256
from cfg import config
from datetime import datetime

app = Flask(__name__)
app.config["MONGO_URI"] = config["mongo_uri"]
mongo = PyMongo(app)
app.secret_key = b'_5#y2Lj/.,yrhj4hy56'


@app.route('/')
def show_index():
    if not 'user_token' in session:
        return redirect('/login')

    return "This is home page"


@app.route('/login')
def show_login():
    signup_success = ''
    if 'signup_success' in session:
        signup_success = session['signup_success']
        session.pop('signup_success', None)

    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)

    return render_template('login.html', signup_success=signup_success, error=error)


@app.route('/signup')
def show_signup():
    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)

    return render_template('signup.html', error=error)


@app.route('/check_login', methods=['POST'])
def check_login():
    email = request.form["email"]
    password = request.form["password"]

    # check if email is blank
    if not email:
        session['error'] = "Email is required!"
        return redirect('/login')

    # check if password is blank
    if not password:
        session['error'] = "Password is required!"
        return redirect('/login')

    user_document = mongo.db.users.find_one({"email": email})
    if user_document is None:
        session['error'] = "Account with this email does not exist"
        return redirect('/login')

    password_hash = sha256(password.encode('utf-8')).hexdigest()

    if user_document['password'] != password_hash:
        session['error'] = "Password is incorrect!"
        return redirect('/login')

    return redirect('/')


@app.route('/handle_signup', methods=['POST'])
def handle_signup():
    try:
        email = request.form["email"]
    except KeyError:
        email = ''

    try:
        password = request.form["password"]
    except KeyError:
        password = ''

    # check if email is blank
    if not email:
        session['error'] = "Email is required!"
        return redirect('/signup')

    # check if password is blank
    if not password:
        session['error'] = "Password is required!"
        return redirect('/signup')

    '''check if email is valid
        check if password is valid - use regex'''

    matching_user_count = mongo.db.users.count_documents({"email": email})
    if matching_user_count > 0:
        session["error"] = "Email already exists!"
        return redirect('/signup')

    password = sha256(password.encode('utf-8')).hexdigest()

    # Create user account in database
    result = mongo.db.users.insert_one({
            "email":email,
            "password": password,
            "name": '',
            "last_login_date": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })

    # If successfully created account, redirect to login page
    session['signup_success'] = "Account created! You can login now"
    return redirect('/login')





