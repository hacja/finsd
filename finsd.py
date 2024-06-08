from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from email_validator import validate_email, EmailNotValidError
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'users.db'
EMAIL_VERIFICATION_CODES = {}

# 表单类
class RegisterForm(FlaskForm):
   username = StringField('Username', validators=[DataRequired()])
   email = StringField('Email', validators=[DataRequired(), Email()])
   password = PasswordField('Password', validators=[DataRequired()])
   confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
   submit = SubmitField('Register')

class LoginForm(FlaskForm):
   email = StringField('Email', validators=[DataRequired(), Email()])
   password = PasswordField('Password', validators=[DataRequired()])
   submit = SubmitField('Login')

class VerifyForm(FlaskForm):
   code = StringField('Verification Code', validators=[DataRequired()])
   submit = SubmitField('Verify')

# 初始化数据库
def init_db():
   with sqlite3.connect(DATABASE) as conn:
       cursor = conn.cursor()
       cursor.execute('''CREATE TABLE IF NOT EXISTS users (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           username TEXT NOT NULL,
           email TEXT NOT NULL UNIQUE,
           password TEXT NOT NULL
       )''')
       conn.commit()

@app.route('/')
def index():
   if 'email' in session:
       return redirect(url_for('welcome'))
   return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()
   if form.validate_on_submit():
       username = form.username.data
       email = form.email.data
       password = form.password.data

       try:
           validate_email(email)
       except EmailNotValidError:
           flash('Invalid email address.', 'error')
           return render_template('register.html', form=form)

       with sqlite3.connect(DATABASE) as conn:
           cursor = conn.cursor()
           cursor.execute("SELECT * FROM users WHERE email = ? OR username = ?", (email, username))
           user = cursor.fetchone()
           if user:
               flash('Email or username already exists.', 'error')
               return redirect(url_for('register'))

           verification_code = random.randint(100000, 999999)
           EMAIL_VERIFICATION_CODES[email] = verification_code

           send_verification_email(email, verification_code)

           session['temp_user'] = {
               'username': username,
               'email': email,
               'password': password
           }
           return redirect(url_for('verify'))

   return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if form.validate_on_submit():
       email = form.email.data
       password = form.password.data

       with sqlite3.connect(DATABASE) as conn:
           cursor = conn.cursor()
           cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
           user = cursor.fetchone()
           if user:
               session['email'] = email
               return redirect(url_for('welcome'))
           else:
               flash('Invalid email or password.', 'error')

   return render_template('login.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
   form = VerifyForm()
   if 'temp_user' not in session:
       return redirect(url_for('register'))

   if form.validate_on_submit():
       code = form.code.data
       email = session['temp_user']['email']

       if email in EMAIL_VERIFICATION_CODES and EMAIL_VERIFICATION_CODES[email] == int(code):
           with sqlite3.connect(DATABASE) as conn:
               cursor = conn.cursor()
               cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                              (session['temp_user']['username'], email, session['temp_user']['password']))
               conn.commit()

           del EMAIL_VERIFICATION_CODES[email]
           del session['temp_user']
           flash('Verification successful, you can now login.', 'success')
           return redirect(url_for('login'))
       else:
           flash('Invalid verification code.', 'error')

   return render_template('verify.html', form=form)

@app.route('/welcome')
def welcome():
   if 'email' in session:
       return render_template('welcome.html', email=session['email'])
   return redirect(url_for('login'))

def send_verification_email(to_email, code):
   from_email = 'your_email@example.com'
   from_password = 'your_email_password'

   msg = MIMEText(f'Your verification code is {code}')
   msg['Subject'] = 'Email Verification'
   msg['From'] = from_email
   msg['To'] = to_email

   server = smtplib.SMTP_SSL('smtp.example.com', 465)
   server.login(from_email, from_password)
   server.sendmail(from_email, [to_email], msg.as_string())
   server.quit()

if __name__ == '__main__':
   init_db()
   app.run(host='0.0.0.0', port=5000, debug=True)
