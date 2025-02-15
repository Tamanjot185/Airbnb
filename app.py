from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
import bcrypt
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)

# User model
class User(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column("name", db.String(100), unique=True)
    email = db.Column("email", db.String(100), unique=True)
    password = db.Column("password", db.String(200))  # Store hashed password

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password

# Forms for login and registration
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Home page
@app.route('/')
def home():
    return render_template("homepage.html")

# View all users (for admin purposes)
@app.route("/view")
def view():
    return render_template("view.html", values=User.query.all())


# Register route
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            # Create new user and add to database
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            # Flash success message
            flash("Registered successfully!", "success")

            return redirect(url_for("login"))
        
        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            flash("Registration failed. Email may already be in use.", "danger")
            print(f"Error: {e}")
        
        finally:
            db.session.close()  # Close the session to prevent locks

    return render_template('register.html', form=form)


# Login route
@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()

    if request.method == "POST":
        if login_form.validate_on_submit():
            email = login_form.email.data
            password = login_form.password.data
            found_user = User.query.filter_by(email=email).first()

            if found_user and bcrypt.checkpw(password.encode('utf-8'), found_user.password.encode('utf-8')):  # Validate the password
                session["user"] = found_user.name
                session["email"] = found_user.email
                flash("Login successful!")
                return redirect(url_for("user"))
            else:
                flash("Invalid credentials. Please try again.", "warning")
                return redirect(url_for("login"))

    return render_template('login.html', login_form=login_form)


# User profile page (after login)
@app.route("/user", methods=["POST", "GET"])
def user():
    email = None
    if "user" in session:
        user = session["user"]

        # Handle email update
        if request.method == "POST":
            email = request.form["email"]
            session["email"] = email
            found_user = User.query.filter_by(name=user).first()
            found_user.email = email
            db.session.commit()
            flash("Email was saved")

        else:
            if "email" in session:
                email = session['email']

        return render_template("user.html", email=email)
    else:
        flash("You are not logged in! Please log in to access your profile.", "warning")
        return redirect(url_for("login"))


# Logout route
@app.route("/logout")
def logout():
    flash("You have been logged out!", "info")
    session.pop("user", None)
    session.pop("email", None)
    return redirect(url_for("login"))

@app.route('/gurugram')
def cozy():
    return render_template('gurugram.html')
    

# Create the database and tables
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
