
# A very simple Flask Hello World app for you to get started with...
from newsapi import NewsApiClient
from googletrans import Translator
# from time import sleep
# from newspaper.article import ArticleException, ArticleDownloadState
from newspaper import Article
from newspaper import Config
from flask import Flask, render_template, url_for, redirect, request
import psycopg2
from flask import Flask,render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required,UserMixin
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError













app = Flask(__name__)
app.config['SECRET_KEY'] = 'A key here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@host/database_name'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_RECYCLE'] = 299
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'example@gmail.com'
app.config['MAIL_PASSWORD'] = 'Password'
mail = Mail(app)





#user and models
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.BigInteger().with_variant(db.Integer, "mysqlclient"), primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)



    def __repr__(self):
        return  User('{self.username}', '{self.email}')







#forms for register,login,reset password
class RegistrationForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(), Length(min=4, max=20)])
    name = StringField('Name',validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), Length(min=8), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired() , Length(min=8)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), Length(min=8), EqualTo('password')])
    submit = SubmitField('Reset Password')





import requests
url = ('https://newsapi.org/v2/top-headlines?'
       'sources=the-times-of-india&financial-times&'
       'apiKey=APIKEY')
r_news= requests.get(url)
all_art = r_news.json()




art = NewsApiClient(api_key='APIKEY')
# all_art = art.get_top_headlines()
articles = all_art['articles']


@app.route("/",methods=['GET','POST'])
def home():
    if request.method == 'POST':
        topic= request.form['topic']
        return redirect(url_for('search',topic=topic))
    else:

        return render_template('home.html',articles=articles)


@app.route("/article",methods=['GET'])
def article():
    try:
        if request.method == 'POST':
            topic= request.form['topic']
            return redirect(url_for('search',topic=topic))
        else:
            url = str(request.args.get("art"))
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
            config = Config()
            config.browser_user_agent = user_agent
            article = Article(url,config=config)
            article.download()
            article.parse()
            article.nlp()
            # print("ERRORS IN PARSING ARTICLE")
            return render_template('article.html', title='Article',article=article)

    except:
        return render_template('error.html', title='Article')







    if request.method == 'POST':
        topic= request.form['topic']
        return redirect(url_for('search',topic=topic))
    else:
        url = str(request.args.get("art"))
        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
        config = Config()
        config.browser_user_agent = user_agent
        article = Article(url,config=config)
        article.download()
        article.parse()
        article.nlp()
        # print("ERRORS IN PARSING ARTICLE")
        return render_template('article.html', title='Article',article=article)

@app.route("/translated",methods=['GET'])
def translated():
    if request.method == 'POST':
        topic= request.form['topic']
        return redirect(url_for('search',topic=topic))
    else:
        url = str(request.args.get("url"))
        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
        config = Config()
        config.browser_user_agent = user_agent
        article = Article(url,config=config)
        article.download()
        article.parse()
        article.nlp()
        l1=[]
        tr = Translator()
        l1.append(tr.translate(str(article.title),dest='hi').text)
        l1.append(tr.translate(str(article.summary),dest='hi').text)
        l1.append(article.top_image)
        l1.append(article.authors)
        # print("ERRORS IN PARSING ARTICLE")
        return render_template('translate.html', title='Hindi',article=l1)



@app.route("/contact",methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        topic= request.form['topic']
        return redirect(url_for('search',topic=topic))
    else:
        return render_template('contact.html')

@app.route("/signup",methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = (bcrypt.generate_password_hash(form.password.data)).decode('utf-8')
        user = User(username=form.username.data,name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template("signup.html", title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login Successfull To Your Account', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash('Logout Successfull From Your Account', 'success')
    return redirect(url_for('home'))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='TheraChatbot@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
This is an auto-generated message.
Team TheraChat.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! ', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route("/<topic>",methods=['GET','POST'])
def search(topic):
    if request.method == 'POST':
        topic= request.form['topic']
        return redirect(url_for('search',topic=topic))
    else:
        topic= str(topic)

        topic_art = art.get_everything(q=topic,language='en',sort_by='relevancy',page=1)
        topic_art = topic_art['articles']
        return render_template('search.html',articles=topic_art)
