from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import date
import smtplib

app = Flask(__name__)
app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


db.create_all()

current_year = date.today().year

OWN_EMAIL = "rohitsharma23329449@gmail.com"
OWN_PASSWORD = "rohitrohitrohit"


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/home')
@login_required
def home():
    return render_template("index.html",  logged_in=True, year=current_year, name=current_user.name)


@app.route("/categories/")
@login_required
def categories():
    return render_template("categories.html", logged_in=current_user.is_authenticated)


@app.route("/anime-details/")
@login_required
def anime_details():
    return render_template("anime-details.html", logged_in=current_user.is_authenticated)


@app.route("/anime-watching/")
@login_required
def anime_watching():
    return render_template("anime-watching.html", logged_in=current_user.is_authenticated)


@app.route("/blog-details/")
def blog_details():
    return render_template("blog-details.html", logged_in=current_user.is_authenticated)


@app.route("/blog/")
def blog():
    return render_template("blog.html", logged_in=current_user.is_authenticated)


@app.route('/signup/', methods=["GET", "POST"])
def signup():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        send_email_to_owner(request.form.get('email'))
        send_email_to_user(request.form.get('email'))
        return redirect(url_for("home"))

    return render_template("signup.html", logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def send_email_to_owner(email):
    email_message = f"Subject:New User Registered\n\nEmail: {email}\n A new user has created an account and logged in"
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(OWN_EMAIL, OWN_PASSWORD)
        connection.sendmail(OWN_EMAIL, OWN_EMAIL, email_message)


def send_email_to_user(email):
    email_message = f"Subject:thank you for logging into otaku|world\n\nPlease give feedback or any kind" \
                    f" of suggestion will be great"
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(OWN_EMAIL, OWN_PASSWORD)
        connection.sendmail(OWN_EMAIL, email, email_message)


if __name__ == "__main__":
    app.run(debug=True)
