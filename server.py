import pymongo
from flask import Flask, abort, render_template, request, redirect, session, flash
from flask_pymongo import PyMongo
from hashlib import sha256
from cfg import config
from datetime import datetime
from utils import get_random_string

app = Flask(__name__)
app.config["MONGO_URI"] = config["mongo_uri"]
mongo = PyMongo(app)
app.secret_key = b'_5#y2Lj/.,yrhj4hy56'


@app.route('/')
def show_index():
    if not 'user_token' in session:
        session["error"] = "You must first login"
        return redirect('/login')

    # Validate user token
    token_document = mongo.db.user_tokens.find_one({
        "sessionHash": session["user_token"]
    })

    if token_document is None:
        session.pop('user_token', None)
        session["error"] = "You must first login"
        return redirect('/login')

    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)

    userId = token_document["userId"]

    user = mongo.db.users.find_one({
        '_id': userId
    })

    uploaded_files = mongo.db.files.find({
        "userId": userId,
        "isActive": True
        }).sort([("createdAt", pymongo.DESCENDING)])

    return render_template('files.html',
                           uploaded_files=uploaded_files,
                           user=user,
                           error=error)


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

    # Verify that password hash matches with original
    if user_document['password'] != password_hash:
        session['error'] = "Password is incorrect!"
        return redirect('/login')

    # Generate token and save it in session
    random_string = get_random_string()
    random_session_hash = sha256(random_string.encode('utf-8')).hexdigest()
    token_object = mongo.db.user_tokens.insert_one({
            "userId": user_document["_id"],
            "sessionHash": random_session_hash,
            "createdAt": '',
            })
    session["user_token"] = random_session_hash

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
        session["error"] = "Account with this email address already exists!"
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

@app.route('/logout')
def logout_user():
    session.pop("user_token", None)
    session['signup_success'] = "You are now logged out"
    session.pop('signup_success', None)
    return redirect('/login')

ALLOWED_EXTENSIONS = {"jpg", "gif", "png", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "csv", "txt"}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/handle_file_upload', methods=['POST'])
def handle_upload():
    if 'UploadedFile' not in request.files:
        session['error'] = "File not uploaded"
        return redirect('/')

    file = request.files["UploadedFile"]

    if file.filename == '':
        session['error'] = "No file selected. Please select a file to upload."
        return redirect('/')

    if not allowed_file(file.filename):
        session["error"] = '.' + file.filename.rsplit('.', 1)[1] + " file format is not supported.  Please upload file with different format."
        return redirect('/')

    return "File Upload yet to be handled"








