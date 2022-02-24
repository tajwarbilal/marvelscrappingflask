from flask import Flask, render_template, redirect, url_for, request
from bs4 import BeautifulSoup
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pathlib
import os
import requests


PARENT_PATH = str(pathlib.Path(__file__).parent.resolve())
UPLOAD_FOLDER = PARENT_PATH + '/static/upload'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# define base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hellowehavesomedata'

# sqlalchemy .db location (for sqlite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
# sqlalchemy track modifications in sqlalchemy
SQLALCHEMY_TRACK_MODIFICATIONS = True

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Marvel(UserMixin, db.Model):
    __tablename__ = 'marvel'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    description = db.Column(db.String(300))
    image = db.Column(db.String(300))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    def __init__(self, name, description, image, owner_id):
        self.name = name
        self.description = description
        self.image = image
        self.owner_id = owner_id


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


db.create_all()
db.session.commit()


@app.route('/')
def index():
    marvel = Marvel.query.all()
    return render_template('index.html', marvel=marvel)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return redirect(url_for('login'))
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)



@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    marvel = Marvel.query.filter_by(owner_id=current_user.id)
    if request.method == 'POST':
        name = request.form.get('name')
        name = name.replace(' ', '_')
        url = "https://marvel.fandom.com/wiki/{}".format(name)
        r = requests.get(url)
        htmlcontent = r.content
        soup = BeautifulSoup(htmlcontent, 'html.parser')
        paras = soup.find('p').get_text()

        print(paras)

        divdata = soup.find('div', {"class": "mw-parser-output"})

        if divdata:
            description = paras
            image = divdata.img.get('data-src')
            owner_id = current_user.id
            entry = Marvel(name=name, description=description,
                           image=image, owner_id=owner_id)
            db.session.add(entry)
            db.session.commit()

    return render_template('dashboard.html', name=current_user.username, id=current_user.id, marvel=marvel)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/delete/<int:id>')
def delete_data(id):
    delete_marvel = Marvel.query.filter_by(id=id).first()
    db.session.delete(delete_marvel)
    db.session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
