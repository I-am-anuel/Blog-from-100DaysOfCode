import os
from dotenv import load_dotenv

from datetime import date
from typing import List

import sqlalchemy.exc
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

ERROR = None

load_dotenv(dotenv_path=".env")
SECRET_KEY = os.environ.get("SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# TODO: Create a User table for all your registered users.
class User(db.Model, UserMixin):
    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(250), nullable=False)
    email = db.Column(String(250), nullable=False, unique=True)
    password = db.Column(String(250), nullable=False)
    posts = db.relationship("BlogPost", backref="user")
    comments = db.relationship("Comment", backref="user")


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(Integer, primary_key=True)
    title = db.Column(String(250), unique=True, nullable=False)
    subtitle = db.Column(String(250), nullable=False)
    date = db.Column(String(250), nullable=False)
    body = db.Column(Text, nullable=False)
    author = db.Column(String(250), nullable=False)
    img_url = db.Column(String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comments = db.relationship("Comment", backref="blog_posts")


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(Integer, primary_key=True)
    text = db.Column(Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


with app.app_context():
    # db.drop_all()
    db.create_all()
    # db.session.query(User).delete()
    # emma = User(name="Emmanuel", email="ricrd.n.emmauel@gmail.com", password="ndknkksdnck")
    # post = BlogPost(title="First Post", user=emma)
    # db.session.add(emma)
    # db.session.add(post)
    # db.session.commit()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    global ERROR
    if register_form.validate_on_submit():
        p_hash = generate_password_hash(
            password=request.form.get("password"),
            method='pbkdf2',
            salt_length=10
        )
        email = register_form.email.data
        if not db.session.execute(db.select(User).where(User.email == email)).scalar():
            new_user_db = User(
                name=request.form.get("name"),
                email=request.form.get("email"),
                password=p_hash,
            )
            db.session.add(new_user_db)
            db.session.commit()

            # This line will authenticate the user with Flask-Login
            login_user(new_user_db, remember=True)
            return redirect(url_for("get_all_posts"))

        else:
            ERROR = "This user email already exist.\nLogin Instead."
            return redirect(url_for("login"))

    return render_template("register.html", form=register_form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    global ERROR
    if login_form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
        inputted_pw = request.form.get("password")
        pw_hash = user.password
        login_user(user=user, remember=True)
        if check_password_hash(pwhash=pw_hash, password=inputted_pw):
            print("I'm in")
            return redirect(url_for("get_all_posts"))
        else:
            ERROR = "Password Incorrect. Try Again!"
            return redirect(url_for("login"))

    return render_template("login.html", form=login_form, error=ERROR)


@app.route('/logout')
@login_required
def logout():
    if logout_user():
        return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    admin = db.get_or_404(entity=User, ident=1)
    return render_template(
        "index.html",
        all_posts=posts,
        logged_in=current_user.is_authenticated,
        admin=admin
    )


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment = CommentForm()
    post = post_id
    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='retro',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)
    requested_post = db.get_or_404(BlogPost, post_id)
    coms = db.session.execute(db.select(Comment).where(Comment.post_id == requested_post.id)).scalars()
    for_email = db.session.execute(db.select(Comment).where(Comment.post_id == requested_post.id)).scalars()
    all_comment = db.session.execute(db.select(Comment).where(Comment.post_id == requested_post.id)).scalars()
    comments = [comment for comment in all_comment]
    commenters = [db.get_or_404(entity=User, ident=comment.user_id).name for comment in coms]
    emails = [db.get_or_404(entity=User, ident=email.user_id).email for email in for_email]
    if comment.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment.comment.data,
                user=current_user,
                blog_posts=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post))
        else:
            global ERROR
            ERROR = "To make comments, you must login first."
            return redirect(url_for("login"))

    return render_template(
        "post.html",
        index=len(commenters),
        post=requested_post,
        form=comment,
        comments=comments,
        commenters=commenters,
        emails=emails
    )


def admin_only(function):
    @wraps(function)
    def decorator_function(*args, **kwargs):
        if current_user:
            if current_user.id != 1:
                return abort(403)
        return function(*args, **kwargs)
    return decorator_function


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user=current_user,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@admin_only
@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    # app.run(port=5002)
    app.run(debug=False, port=5002)
