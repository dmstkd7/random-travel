# -*- coding: utf-8 -*-
"""
	this is random travel plan web
	
	author : Eunsang Jang
	date : 2016-08-03
	
"""

from flask import Flask, flash, abort, request, url_for, render_template, redirect,g
import Session
from mongoengine import *
import hashlib, uuid
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.session_interface = Session.MongoSessionInterface(db='Test')
app.config.update(
	SESSION_COOKIE_NAME='test_session'
)

connect('Test', host="223.194.70.126", port=27017)



class User(Document):
	name = StringField(max_length=50)
	email = StringField(required=True)
	password = StringField(max_length=500)




@app.before_request
def before_request():
	g.user=None



@app.route('/')
@app.route('/home')
def home():
	"this is main view "
	return "hello this is home"



@app.route('/login', methods=['GET', 'POST'])
def login():
	"""Logs the user in. """
	if g.user:
		return redirect(url_for('timeline'))
	error = None

	if request.method == 'POST':
		print "this is request form"
		print request.form['username']
		user = User.objects(name=request.form['username']).first()
		print user.name
		if user is None:
			error = 'Invalid username'
		elif not check_password_hash(user.password, request.form['password']):
			error = 'Invalid password'
		else:
			flash('You were logged in')
			#session['user_id'] = user.name
			return redirect(url_for('timeline'))
	return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
	""" Registers the users."""
	
	error = None
	if request.method == 'POST':
		if not request.form['username']:
			error = 'You have to enter a valid email address'
		elif not request.form['email'] or \
				'@' not in request.form['email']:
			error = 'You have to enter a valid email address'
		elif not request.form['password']:
			error = 'You have to enter a password'
		elif request.form['password'] != request.form['password2']:
			error = 'The two passwords do not match'
		elif User.objects(name=request.form['username']).first() is not None:
			error = 'The username is already taken'
		else:
			newUser = User(email= request.form['email'],
							name = request.form['username'],
							password = generate_password_hash(request.form['password']))
			newUser.save()
			flash('You were successfully registered and can login now')
			return redirect(url_for('login'))

	return render_template('register.html', error=error)


@app.route('/timeline')
def timeline():
	return "Not yet"


@app.route('/public_timeline')
def public_timeline():
	return "Not yet"

@app.route('/logout')
def logout():
	"""Logs the user out."""
	return redirect(url_for('home'))


@app.route('/leave', methods=['GET', 'POST'])
def leave():
	"""leave the users"""


	return "this is leave view"


@app.route("/session_in")
def session_signin():
	session['test'] = "abc"
	return "Session Signin"


@app.route("/session_out")
def session_signout():
	session.clear()
	return "Session Signout"

@app.route("/session_start")
def session_start():
	print(session.get("test", "Empty Data"))
	return "Session Start Print to Console"






if __name__ == '__main__':
	app.run(host="0.0.0.0")
