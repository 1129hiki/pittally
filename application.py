import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required
import psycopg2


# Configure application
app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)
    

db = SQL(os.environ.get("DATABASE_URL")
or "sqlite:///matching.db")

# Loading database
db = SQL("sqlite:///matching.db")

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/', methods=["GET","POST"])
@login_required
def matching():
    if request.method == "POST":
        # get userid
        user_id = session.get("user_id")

        # get userid of who to match/unmatch
        id_to_match = request.form.get("match")
        id_to_unmatch = request.form.get("unmatch")

        # get matching information of user
        matching_list = str(db.execute("SELECT matches FROM users WHERE id = ?;", user_id)[0]["matches"])

        # check if id_to_match is not None. Produce key by sadwitching user id to match with "/"
        # Updata matches in users table if user to match is not in the users matches.
        # else, flash message that user to match is already in matches
        if id_to_match != None:
            matching_key = "/" + str(id_to_match) + "/"
            if not(matching_key in matching_list):
                matching_list = matching_list + matching_key
                db.execute("UPDATE users SET matches = ? WHERE id = ?;", matching_list, user_id)
                flash("You liked this user!")
                return redirect("/")
            else:
                flash("You already liked this user.")
                return redirect("/")

        # check if id_to_unmatch is not None. Produce key by sadwitching user id to unmatch with "/"
        # Updata matches in users table if user to unmatch is in the users matches.
        # else, flash message that user to unmatch is not in your matches
        else:
            unmatching_key = "/" + str(id_to_unmatch) + "/"
            if unmatching_key in matching_list:
                matching_list = matching_list.replace(unmatching_key, '')
                db.execute("UPDATE users SET matches = ? WHERE id = ?;", matching_list, user_id)
                flash("You unliked this user")
                return redirect("/")
            else:
                flash("You have not liked this user")
                return redirect("/")

        if keyword_to_search != None:
            # get information of user
            user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)
            usertype = user_info[0]["type"]

            if usertype == "marketer":

                creator_list = []
                for i in range(len(creator_sql)):
                    creator_list.append(creator_sql[i])
                return render_template("matching.html", show_user=creator_list)

            if usertype == "creator":
                marketer_sql =  db.execute("""SELECT id, name, skill, description FROM users WHERE type = "marketer";""")
                marketer_list = []
                for i in range(len(marketer_sql)):
                    marketer_list.append(marketer_sql[i])
                return render_template("matching.html", show_user=marketer_list)

    else:
        # get userid
        user_id = session.get("user_id")

        # get information of user
        user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        usertype = user_info[0]["type"]

        # get keyword for search
        keyword_to_search = "%" + str(request.args.get("keyword")) + "%"

        if usertype == "marketer":
            if keyword_to_search != "%None%":
                creator_sql =  db.execute("""SELECT id, name, skill, description FROM users
                                          WHERE type = "creator" AND (name LIKE ? OR skill LIKE ? OR description LIKE ?);""",
                                          keyword_to_search, keyword_to_search, keyword_to_search)
            else:
                creator_sql =  db.execute("""SELECT id, name, skill, description FROM users WHERE type = "creator";""")

            creator_list = []
            for i in range(len(creator_sql)):
                creator_list.append(creator_sql[i])
            return render_template("matching.html", show_user=creator_list)

        if usertype == "creator":
            if keyword_to_search != "%None%":
                marketer_sql =  db.execute("""SELECT id, name, skill, description FROM users
                                          WHERE type = "marketer" AND (name LIKE ? OR skill LIKE ? OR description LIKE ?);""",
                                          keyword_to_search, keyword_to_search, keyword_to_search)
            else:
                 marketer_sql =  db.execute("""SELECT id, name, skill, description FROM users WHERE type = "marketer";""")
            marketer_list = []
            for i in range(len(marketer_sql)):
                marketer_list.append(marketer_sql[i])
            return render_template("matching.html", show_user=marketer_list)

        if usertype == None:
            flash("Register your information to be connected with your future fellow!")
            return redirect("/register2")

        return render_template("matching.html")

@app.route("/matched", methods=["GET","POST"])
@login_required
def matched():
    if request.method == "POST":
        # get userid
        user_id = session.get("user_id")

        # get userid of who to unmatch
        id_to_unmatch = request.form.get("unmatch")

        # taken from matching function. allow user to unmatch from this page as well.
        if id_to_unmatch != None:
            # get matching information of user
            matching_list = str(db.execute("SELECT matches FROM users WHERE id = ?;", user_id)[0]["matches"])

            # creating unmatching key
            unmatching_key = "/" + str(id_to_unmatch) + "/"

            # reflect unmatch to database
            matching_list = matching_list.replace(unmatching_key, '')
            db.execute("UPDATE users SET matches = ? WHERE id = ?;", matching_list, user_id)

            # notify you unliked user
            flash("You unliked this user")
            return redirect("/matched")

        else:
            return redirect("/matched") #TODO display you have no matches

    else:
        # get userid
        user_id = session.get("user_id")

        # get matching list of user
        users_matches = db.execute("SELECT matches FROM users WHERE id = ?", user_id)[0]["matches"]

        # create matching key of user
        user_key = "/" + str(user_id) + "/"

        # get matching list of all other user
        all_matches = db.execute("SELECT id, name, skill, description, matches, contact FROM users")

        # store mutual matches with user
        mutual_matches = []

        for i in range(len(all_matches)):
            # check if other liked user
            if user_key in str(all_matches[i]["matches"]):
                # check if user liked other
                # creating key for other user
                other_key = "/" + str(all_matches[i]["id"]) + "/"
                if other_key in users_matches:
                    # adding to mutual matches list
                    mutual_matches.append(all_matches[i])

        return render_template("matched.html",mutual_matches=mutual_matches)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # get value from form
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        usertype = request.form.get("usertype")
        skills = request.form.get("skill")

        # return 1 if username or email is already used. 0 otherwise.
        username_used = db.execute("SELECT name FROM users WHERE name = ?", username)
        email_used = db.execute("SELECT email FROM users WHERE email = ?", email)

        # store error message
        message = []

        # ensure username is filled and not priviously used.
        if not username:
            message.append("Username is not filled")
        if len(username_used) == 1:
            message.append("This username is already taken")

        # ensure email is filled and not priviously used.
        if not email:
            message.append("Email is not filled")
        if len(email_used) == 1:
            message.append("This email is already used")

        # ensure password is filled and satisfy condition
        # condition: more than 8 characters
        if len(password) < 8:
            message.append("Password have to be at least 8 characters")

        # return template with warning message if error occured.
        if (not username) or (len(username_used) == 1) or (not email) or (len(email_used) == 1) or (len(password) < 8):
            return render_template("register.html",message=message)

        # generate hashed password
        hashed_password = generate_password_hash(password)

        # save username, email and hashed password in users table in matching.db
        db.execute("INSERT INTO users (name, email, hash) VALUES(?, ?, ?);", username, email, hashed_password)

        # redirecting for requesting more information
        return redirect("/register2")

    else:
        return render_template("register.html")

@app.route("/register2", methods=["GET", "POST"])
@login_required
def register2():
    if request.method == "POST":
        #get user id
        user_id = session.get("user_id")

        # store error message
        message = []

        # get value from form
        usertype = request.form.get("usertype")
        skill = request.form.get("skill")
        description = request.form.get("description")
        contact = request.form.get("contact")

        # ensure usertype (marketer or creator is selected)
        if not usertype:
            message.append("You have to choose either marketer or creator")

        # ensure skill form and description form is filled
        # skill form is used for creator to write what is their product.
        # skiil form is used for marketer to write how they can sell product.
        if (not skill) or (not description) or (not contact):
            message.append("Form is not filled")

        # ensure user choose either marketer or creator
        if not (usertype == "marketer" or usertype == "creator"):
            message.append("You can choose from either marketer or creator")

        # return template with warning message if error occured.
        if (not usertype) or (not skill) or (not description) or (not contact) or not(usertype == "marketer" or usertype == "creator"):
            return render_template("register2.html", message=message)

        # save usertype, skill, and description to "users" table in matching.db
        db.execute("UPDATE users SET type=?, skill=?, description=?, contact=? WHERE id = ?;", usertype, skill, description, contact, user_id)

        return redirect("/")

    else: return render_template("register2.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # store error message
        message = []

        # get information from form
        email = request.form.get("email")
        password = request.form.get("password")

        # get information from database
        user_info = db.execute("SELECT * FROM users WHERE email = ?", email)

        # ensure email is filled
        if not email:
            message.append("Email is not filled")
            return render_template("login.html",message=message)

        # ensure email is registerd. if length of user_info is 0, it means the email adress filled is not registerd.
        if len(user_info) == 0:
            message.append("This email is not registerd")
            return render_template("login.html",message=message)

        # check password provided matches with the hased password assoiated with the email
        password_hashed = user_info[0]["hash"]
        if not (check_password_hash(password_hashed, password)):
            message.append("Password does not match")
            return render_template("login.html",message=message)

        # return template with warning message if error occured
        if (not email) or (len(user_info) == 0) or (not (check_password_hash(password_hashed, password))):
            return render_template("login.html",message=message)

        # Remember which user has logged in
        session["user_id"] = user_info[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    #get user id
    user_id = session.get("user_id")

    #get information
    user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)

    return render_template("profile.html", user_info=user_info)

@app.route("/change-profile", methods=["GET", "POST"])
@login_required
def change_profile():
    #get user id
    user_id = session.get("user_id")

    #get information
    user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)

    if request.method == "POST":
        new_username = request.form.get("username")
        new_email = request.form.get("email")

        if new_username:
            # check username does not exist
            # return 1 if username is already used. 0 otherwise.
            username_used = db.execute("SELECT name FROM users WHERE name = ?;", new_username)
            if len(username_used) == 1:
                flash("This username is already taken")
                return redirect("/change-profile")
            else:
                db.execute("UPDATE users SET name=? WHERE id=?", new_username, user_id)
                flash("Username is successfully changed")
                return redirect("/profile")

        if new_email:
            # check email does not exist
            # return 1 if email is already used. 0 otherwise.
            email_used = db.execute("SELECT email FROM users WHERE email = ?;", new_email)
            if len(email_used) == 1:
                flash("This email is already used")
                return redirect("/change-profile")
            else:
                db.execute("UPDATE users SET email=? WHERE id=?;", new_email, user_id)
                flash("Email is successfully changed")
                return redirect("/profile")

        else:
            return redirect("/change-profile")

    else:
        return render_template("change_profile.html")

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    #get user id
    user_id = session.get("user_id")

    if request.method == "POST":
        #get information
        old_password_hash = db.execute("SELECT hash FROM users WHERE id = ?;", user_id)[0]["hash"]
        input_password = request.form.get("input_password")
        new_password = request.form.get("new_password")
        new_password_conf = request.form.get("new_password_conf")

        if not (check_password_hash(old_password_hash, input_password)):
            flash("Incorrect password")
            return redirect("/change-password")

        if new_password != new_password_conf:
            flash("Password does not match")
            return redirect("/change-password")

        if len(new_password) < 8:
            flash("Password have to be at least 8 characters")
            return redirect("/change-password")

        else:
            new_hashed_password = generate_password_hash(new_password)
            db.execute("UPDATE users SET hash = ? WHERE id = ?;", new_hashed_password, user_id)
            flash("Password is successfully changed")
            return redirect("/profile")

    else:
        return render_template("change_password.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")