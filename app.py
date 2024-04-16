#!/usr/bin/env python3

import os
import sys
import subprocess
import datetime

from flask import Flask, render_template, request, redirect, url_for, make_response

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

# import logging
import sentry_sdk
from sentry_sdk.integrations.flask import (
    FlaskIntegration,
)  # delete this if not using sentry.io

# from markupsafe import escape
import pymongo
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId
from dotenv import load_dotenv

# load credentials and configuration options from .env file
# if you do not yet have a file named .env, make one based on the template in env.example
load_dotenv(override=True)  # take environment variables from .env.

# initialize Sentry for help debugging... this requires an account on sentrio.io
# you will need to set the SENTRY_DSN environment variable to the value provided by Sentry
# delete this if not using sentry.io
sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    # enable_tracing=True,
    # Set traces_sample_rate to 1.0 to capture 100% of transactions for performance monitoring.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100% of sampled transactions.
    # We recommend adjusting this value in production.
    integrations=[FlaskIntegration()],
    send_default_pii=True,
)

# instantiate the app using sentry for debugging
app = Flask(__name__)

# # turn on debugging if in development mode
# app.debug = True if os.getenv("FLASK_ENV", "development") == "development" else False

# try to connect to the database, and quit if it doesn't work
try:
    cxn = pymongo.MongoClient(os.getenv("MONGO_URI"))
    db = cxn[os.getenv("MONGO_DBNAME")]  # store a reference to the selected database

    # verify the connection works by pinging the database
    cxn.admin.command("ping")  # The ping command is cheap and does not require auth.
    print(" * Connected to MongoDB!")  # if we get here, the connection worked!
except ConnectionFailure as e:
    # catch any database errors
    # the ping command failed, so the connection is not available.
    print(" * MongoDB connection error:", e)  # debug
    sentry_sdk.capture_exception(e)  # send the error to sentry.io. delete if not using
    sys.exit(1)  # this is a catastrophic error, so no reason to continue to live


# set up the routes


@app.route("/")
def home():
    """
    Route for the home page.
    Simply returns to the browser the content of the index.html file located in the templates folder.
    """
    return render_template("index.html")


@app.route("/read")
def read():
    """
    Route for GET requests to the read page.
    Displays some information for the user with links to other pages.
    """
    docs = db.exampleapp.find({}).sort(
        "created_at", -1
    )  # sort in descending order of created_at timestamp
    return render_template("read.html", docs=docs)  # render the read template


@app.route("/create")
def create():
    """
    Route for GET requests to the create page.
    Displays a form users can fill out to create a new document.
    """
    return render_template("create.html")  # render the create template


@app.route("/create", methods=["POST"])
def create_post():
    if not current_user.is_authenticated:
        flash('You must be logged in to post messages.')
        return redirect(url_for('login'))

    name = request.form["fname"]
    message = request.form["fmessage"]
    user_id = current_user.id

    doc = {
        "name": name,
        "message": message,
        "created_at": datetime.datetime.utcnow(),
        "user_id": user_id
    }
    db.exampleapp.insert_one(doc)
    return redirect(url_for("read"))

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # make sure 'login' is the endpoint for your login route

@login_manager.user_loader
def load_user(user_id):
    # Your logic to load a user from the database by user_id
    return User.get(user_id)



@app.route("/edit/<mongoid>")
def edit(mongoid):
    """
    Route for GET requests to the edit page.
    Displays a form users can fill out to edit an existing record.

    Parameters:
    mongoid (str): The MongoDB ObjectId of the record to be edited.
    """
    doc = db.exampleapp.find_one({"_id": ObjectId(mongoid)})
    return render_template(
        "edit.html", mongoid=mongoid, doc=doc
    )  # render the edit template


@app.route("/edit/<mongoid>", methods=["POST"])
def edit_post(mongoid):
    """
    Route for POST requests to the edit page.
    Accepts the form submission data for the specified document and updates the document in the database.

    Parameters:
    mongoid (str): The MongoDB ObjectId of the record to be edited.
    """
    name = request.form["fname"]
    message = request.form["fmessage"]

    doc = {
        # "_id": ObjectId(mongoid),
        "name": name,
        "message": message,
        "created_at": datetime.datetime.utcnow(),
    }

    db.exampleapp.update_one(
        {"_id": ObjectId(mongoid)}, {"$set": doc}  # match criteria
    )

    return redirect(
        url_for("read")
    )  # tell the browser to make a request for the /read route




@app.route("/webhook", methods=["POST"])
def webhook():
    """
    GitHub can be configured such that each time a push is made to a repository, GitHub will make a request to a particular web URL... this is called a webhook.
    This function is set up such that if the /webhook route is requested, Python will execute a git pull command from the command line to update this app's codebase.
    You will need to configure your own repository to have a webhook that requests this route in GitHub's settings.
    Note that this webhook does do any verification that the request is coming from GitHub... this should be added in a production environment.
    """
    # run a git pull command
    process = subprocess.Popen(["git", "pull"], stdout=subprocess.PIPE)
    pull_output = process.communicate()[0]
    # pull_output = str(pull_output).strip() # remove whitespace
    process = subprocess.Popen(["chmod", "a+x", "flask.cgi"], stdout=subprocess.PIPE)
    chmod_output = process.communicate()[0]
    # send a success response
    response = make_response(f"output: {pull_output}", 200)
    response.mimetype = "text/plain"
    return response


@app.errorhandler(Exception)
def handle_error(e):
    """
    Output any errors - good for debugging.
    """
    return render_template("error.html", error=e)  # render the edit template


# run the app
if __name__ == "__main__":
    # logging.basicConfig(filename="./flask_error.log", level=logging.DEBUG)
    app.run(load_dotenv=True)



class User(UserMixin):
    def __init__(self, id):
        self.id = id

    @staticmethod
    def validate_login(password_hash, password):
        return check_password_hash(password_hash, password)

# Flask-Login helper to retrieve a user from our fake database
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Replace with real user lookup logic
def user_lookup(username):
    if username == "admin":
        # Typically this would be a hashed password
        return User("admin"), "example_hashed_password"
    return None, None


from flask import flash
from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user, password_hash = user_lookup(username)
        if user and User.validate_login(password_hash, password):
            login_user(user)
            return redirect(url_for('read'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

from flask_login import current_user



from flask import abort


@app.route("/delete/<mongoid>", methods=["POST"])
@login_required
def delete_post(mongoid):
    # Fetch the document to check ownership
    post = db.exampleapp.find_one({"_id": ObjectId(mongoid)})

    if not post:
        abort(404, description="Post not found")

    # Check if the current user is the post owner or an admin
    # Assuming 'is_admin' is a property of the User model that returns True if the user is an admin
    if current_user.id == post['user_id'] or getattr(current_user, 'is_admin', False):
        db.exampleapp.delete_one({"_id": ObjectId(mongoid)})
        return redirect(url_for('read'))
    else:
        return "Unauthorized", 403


class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

    @staticmethod
    def get(user_id):
        # Logic to retrieve user from the database
        return User(user_id, username='example', is_admin=False)

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId



app.config["MONGO_URI"] = os.getenv("MONGO_URI")  # Ensure this is the correct URI for your MongoDB

mongo = PyMongo(app)  # This initializes the PyMongo object with your Flask app
bcrypt = Bcrypt(app)  # Initialize Bcrypt as well for handling password hashing

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = mongo.db.users  # Accessing the 'users' collection correctly
        existing_user = users.find_one({'username': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            users.insert_one({'username': request.form['username'], 'password': hashpass})
            flash('Registration successful!', 'success')
            return redirect(url_for('index'))  # Make sure 'index' is defined in your routes
        else:
            flash('Username already exists!', 'danger')

    return render_template('register.html')
