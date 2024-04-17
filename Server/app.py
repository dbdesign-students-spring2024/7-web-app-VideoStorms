import os
import sys
import subprocess
import datetime
from flask_bcrypt import Bcrypt
from flask import session

from flask import Flask, render_template, request, redirect, url_for, make_response

from werkzeug.utils import secure_filename




# from markupsafe import escape
import pymongo
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId
from dotenv import load_dotenv

# load credentials and configuration options from .env file
# if you do not yet have a file named .env, make one based on the template in env.example
load_dotenv(override=True)  # take environment variables from .env.

app = Flask(__name__)
bcrypt = Bcrypt(app)

# # turn on debugging if in development mode
# app.debug = True if os.getenv("FLASK_ENV", "development") == "development" else False

app.secret_key = os.getenv('SECRET_KEY')  # Ensure you have SECRET_KEY in your .env file


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
    print(" * MongoDB connection error:", e)  # debugg
    sys.exit(1)  # this is a catastrophic error, so no reason to continue to live


# set up the routes

app.config['UPLOAD_FOLDER'] = 'static/uploads/'

app.config['UPLOAD_FOLDER'] = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure the upload folder exists
def ensure_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Call this function with your upload path at the start of your application
ensure_directory(app.config['UPLOAD_FOLDER'])

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
    if 'username' in session:
        return render_template("create.html")
    return redirect(url_for('login'))

@app.route("/create", methods=["POST"])
def create_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    name = session['username']
    item = request.form['item']
    message = request.form["fmessage"]
    user_id = session['user_id']
    photo = request.files['photo']

    if photo and allowed_file(photo.filename):
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_path)
        photo_url = url_for('static', filename='uploads/' + filename)
    else:
        photo_url = None

    doc = {
        "name": name,
        "item": item,
        "message": message,
        "photo_url": photo_url,
        "created_at": datetime.datetime.utcnow(),
        "user_id": ObjectId(user_id)
    }
    db.exampleapp.insert_one(doc)
    return redirect(url_for("read"))


@app.route("/edit/<mongoid>", methods=["GET", "POST"])
def edit(mongoid):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Determine criteria based on user's role
    if session.get('is_admin', False):
        criteria = {"_id": ObjectId(mongoid)}  # Admin can edit any document
    else:
        criteria = {
            "_id": ObjectId(mongoid),
            "user_id": ObjectId(session['user_id'])  # Non-admins can only edit their own documents
        }

    doc = db.exampleapp.find_one(criteria)
    if doc is None:
        return "Unauthorized", 403  # If no document is found, access is unauthorized

    if request.method == 'POST':
        item = request.form["item"]
        message = request.form["fmessage"]
        photo = request.files['photo']
        old_photo_url = doc.get('photo_url')

        # Check if a new photo has been uploaded
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(photo_path)
            new_photo_url = url_for('static', filename='uploads/' + filename)

            # Replace the old photo with the new photo, if a new one was uploaded
            if old_photo_url and old_photo_url != new_photo_url:
                old_photo_path = os.path.join(app.root_path, old_photo_url[1:])  # Correct path construction
                if os.path.exists(old_photo_path):
                    try:
                        os.remove(old_photo_path)  # Delete the old file
                        app.logger.info(f"Successfully deleted old photo: {old_photo_path}")
                    except Exception as e:
                        app.logger.error(f"Failed to delete old photo: {old_photo_path}. Error: {e}")
                else:
                    app.logger.warning(f"Tried to delete non-existent file: {old_photo_path}")

            photo_url = new_photo_url
        else:
            photo_url = old_photo_url  # No new photo uploaded, keep the old URL

        # Update the document in the database
        update_data = {
            "item": item,
            "message": message,
            "photo_url": photo_url,
            "created_at": datetime.datetime.utcnow()
        }
        db.exampleapp.update_one({"_id": ObjectId(mongoid)}, {"$set": update_data})
        
        return redirect(url_for("read"))

    # If it's a GET request, render the edit page with the document's data
    return render_template("edit.html", mongoid=mongoid, doc=doc)


@app.route("/edit/<mongoid>", methods=["POST"])
def edit_post(mongoid):
    """
    Route for POST requests to the edit page.
    Accepts the form submission data for the specified document and updates the document in the database.
    Parameters:
    mongoid (str): The MongoDB ObjectId of the record to be edited.
    """
    item = request.form["item"]
    message = request.form["fmessage"]

    doc = {
        # "_id": ObjectId(mongoid),
        "item": item,
        "message": message,
        "created_at": datetime.datetime.utcnow(),
    }

    db.exampleapp.update_one(
        {"_id": ObjectId(mongoid)}, {"$set": doc}  # match criteria
    )

    return redirect(
        url_for("read")
    )  # tell the browser to make a request for the /read route


import logging

@app.route("/delete/<mongoid>")
def delete(mongoid):
    if 'username' not in session:
        return redirect(url_for('login'))

    if session.get('is_admin', False):
        criteria = {"_id": ObjectId(mongoid)}
    else:
        user_id = session['user_id']
        criteria = {"_id": ObjectId(mongoid), "user_id": ObjectId(user_id)}

    doc = db.exampleapp.find_one(criteria)
    if not doc:
        return "Unauthorized", 403

    if doc.get('photo_url'):
        try:
            photo_path = os.path.join(app.root_path, doc['photo_url'][1:])
            if os.path.exists(photo_path):
                os.remove(photo_path)
            else:
                logging.error(f"Photo file not found: {photo_path}")
        except Exception as e:
            logging.error(f"Error deleting photo: {e}")

    result = db.exampleapp.delete_one(criteria)
    if result.deleted_count == 0:
        return "Unauthorized", 403

    return redirect(url_for("read"))




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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = {
            "username": username,
            "password": hashed_password
        }

        db.users.insert_one(user)
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.users.find_one({"username": username})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username
            session['user_id'] = str(user['_id'])  # Store user ID from MongoDB in session
            session['is_admin'] = user.get('is_admin', False)  # Set is_admin in session
            return redirect(url_for('home'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the username from the session
    session.pop('user_id', None)  # Remove the user ID from the session
    # Instead of redirecting directly, render the logout message template
    return render_template('logout_message.html')



