from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUser, LoginUser, UserComment
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Base = declarative_base()

# Using Gravatar for the profile picture
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))
# CONFIGURE TABLES


class Users(UserMixin, db.Model):
    __tablename__ = 'users_table'
    id = db.Column(db.Integer, primary_key=True)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')
    email = db.Column(db.String(300), nullable=False)
    password = db.Column(db.String(300), nullable=False)
    username = db.Column(db.String(300), nullable=False)

    def __init__(self, email, password, username):
        self.email = email
        self.password = password
        self.username = username


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users_table.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship('Users', back_populates='posts')
    comments = relationship('Comment', back_populates='rel_blog')

    def __init__(self, author_id, title, subtitle, date, body, img_url):
        self.author_id = author_id
        self.title = title
        self.subtitle = subtitle
        self.date = date
        self.body = body
        self.img_url = img_url


class Comment(db.Model):
    __tablename__ = 'user_comments'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users_table.id'))
    blog__id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    comment_author = relationship('Users', back_populates='comments')
    rel_blog = relationship('BlogPost', back_populates='comments')

    def __init__(self, comment, author_id, blog__id):
        self.comment = comment
        self.author_id = author_id
        self.blog__id = blog__id


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        logged_in = True
    else:
        logged_in = False

    return render_template(
        "index.html",
        all_posts=posts,
        logged_in=logged_in,
        username=current_user,
    )


@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterUser()
    if register_form.validate_on_submit():
        registered_email = Users.query.filter_by(email=register_form.email.data).first()
        if registered_email:
            flash(message='You\'re already registered. Log in instead.')
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(
                password=register_form.password.data,
                method='pbkdf2:sha256',
                salt_length=10
            )
            new_user = Users(
                email=register_form.email.data,
                password=hashed_password,
                username=register_form.username.data,
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginUser()
    user_to_login = Users.query.filter_by(username=login_form.username.data).first()
    if login_form.validate_on_submit():
        if user_to_login:
            if check_password_hash(pwhash=user_to_login.password, password=login_form.password.data):
                login_user(user_to_login)
                flash(message='You\'ve successfully logged in')
                return redirect(url_for('get_all_posts'))
            else:
                flash(message='Wrong password. Try again, fam!')
                return redirect(url_for('login'))
        else:
            flash(message='User doesn\'t exist!')
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(message='Hey, we hate to see you go.')
    return redirect(url_for('get_all_posts', logged_in=False))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
@login_required
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.all()
    form = UserComment()
    if form.validate_on_submit():
        new_comment = Comment(
            comment=form.comment.data,
            author_id=current_user.id,
            blog__id=requested_post.id,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=requested_post.id))
    return render_template(
        "post.html",
        post=requested_post,
        username=current_user,
        logged_in=current_user.is_authenticated,
        form=form,
        comments=comments
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # author=current_user.username,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make_post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template('make_post.html', form=edit_form, is_edit=True, username=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# @app.route('/delete_user/<int:user_id')
# def delete_user(user_id):
#     pass


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
    with app.app_context():
        db.create_all()
