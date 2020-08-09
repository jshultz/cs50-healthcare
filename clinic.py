from flask import (
    Flask, flash, request, redirect, render_template, url_for, session
)

from flask.json import jsonify

from flask_session import Session
from tempfile import mkdtemp

from werkzeug.security import check_password_hash, generate_password_hash

import os
import sqlite3
import datetime
import re

import queries
import helpers

# get secret key from environment variable
# default key for development only
SECRET_KEY = os.environ.get('SECRET_KEY', 'secret-key-shhh')


# initialize flask
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['TEMPLATES_AUTO_RELOAD'] = True


# Don't cache responses
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response


# configure session to use filesystem instead of signed cookies
app.config['SESSION_FILE_DIR'] = mkdtemp()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)


# General user (patient) routes
@app.route('/', methods=['GET'])
@helpers.login_required
def default():

    return render_template('default.html')


@app.route('/profile', methods=['GET'])
@helpers.login_required
def profile():

    user = queries.get_user_from_id(session['user_id'])

    return render_template('profile.html', user=user)


@app.route('/edit_profile', methods=['GET', 'POST'])
@helpers.login_required
def edit_profile():
    """
    Form to allow user to edit their information
    """


    return helpers.apology('not implemented')


@app.route('/messages', methods=['GET'])
@helpers.login_required
def messages():
    """
    Display messages
    """

    arr_messages = queries.get_messages(session['user_id'])

    return render_template('messages.html', messages=arr_messages)


@app.route('/post_new_message', methods=['GET', 'POST'])
@helpers.login_required
def post_new_message():
    """
    Post a message to or from a patient
    """

    user_type = queries.get_user_from_id(session['user_id'])[4]

    patients = [(x[0], f'{ x[1] } { x[2] }')
        for x in queries.get_users_full_name_by_type(0)]

    providers = [(x[0], f'{ x[1] } { x[2] }')
        for x in queries.get_users_full_name_by_type(50)]

    all_users_wo_admin = [j for i in (patients, providers)
        for j in (i if isinstance(i, tuple) else i)]

    if request.method == 'POST':

        sender_id = session['user_id']
        receipient_id = int(request.form.get('receipient', "0"))
        priority = int(request.form.get('priority', "0"))
        subject = request.form.get('subject', 'No subject')
        body = request.form.get('body', None)

        if receipient_id == 0 or not body:
            flash('Errors in form', category='error')
            return redirect(url_for('post_new_message'))


        if receipient_id == -1:

            queries.broadcast(
                all_users_wo_admin,
                {
                    'priority': priority,
                    'sender': sender_id,
                    'receiver': receipient_id,
                    'subject': subject,
                    'body': body
                })

        else:

            queries.post_message(
                {
                    'priority': priority,
                    'sender': sender_id,
                    'receiver': receipient_id,
                    'subject': subject,
                    'body': body
                })

        flash('Message sent!', category='info')
        return redirect(url_for('messages'))

    # if user logged in is an admin
    # generate a list (tuple) of all users
    if user_type == 100:

        # then compine the two tuples

        # add a new option to broadcast
        all_users_wo_admin.insert(0, (-1, 'All users'))

        return render_template('post_message.html', receipients=all_users_wo_admin)

    elif user_type == 50:

        provider_patients = [(x[0], f'{ x[1] } { x[2] }') for x in queries.get_provider_patients(session['user_id'])]

        return render_template('post_message.html', receipients=provider_patients)

    else:

        patient_care = [(x[0], f'{ x[1] } { x[2] }') for x in queries.get_patient_providers(session['user_id'])]

        return render_template('post_message.html', receipients=patient_care)


@app.route('/post_reply', methods=['GET', 'POST'])
@helpers.login_required
def post_reply():

    message = queries.get_message(int(request.args.get("m", "-1")))

    if request.method == 'POST':

        queries.post_message({
            'sender': session['user_id'],
            'receiver': int(request.form.get("receipient_id", "-1")),
            'priority': int(request.form.get("priority", "0")),
            'subject': request.form.get("subject", "RE: No Subject"),
            'body': request.form.get("body", "")
        })

        flash('Message sent!', category='info')
        return redirect(url_for('messages'))

    if not message:

        flash('Message was not found!', category='error')
        return redirect(url_for('messages'))

    return render_template('post_reply.html', message={'id': message[0], 'receipient': f'{ message[4] } { message[5] }', 'subject': message[3]})


@app.route('/message_action', methods=['GET'])
@helpers.login_required
def message_action():
    """
    Shows a confirmation form to allow a user to
    modify message metadata or delete it.
    """

    action = request.args.get("a", "none")
    message_id = int(request.args.get("m", "-1"))

    if action is "none" or message_id == -1:

        flash("Message not found!", category='error')
        return redirect(url_for('messages'))

    if request.method is 'POST':

        action_form = request.form.get("action", "none")

        if action_form is 'mark_read':

            queries.mark_message(0, message_id)

            flash("Message marked as read", category='info')
            return redirect(url_for('messages'))

        elif action_form is 'mark_unread':

            queries.mark_message(1, message_id)

            flash("Message marked as unread", category='info')
            return redirect(url_for('messages'))

        elif action_form is 'archive':

            queries.archive_message(message_id)

            flash("Message archived", category='info')
            return redirect(url_for('messages'))

        elif action_form is 'delete':

            queries.delete_message(message_id)

            flash("Message deleted", category='info')
            return redirect(url_for('messages'))


    return render_template("message_action.html", message={'action': action, 'id': message_id})


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login user"""

    # if a user is already logged in, redirect to home
    if session.get('user_id'):
        return redirect('/')

    # a POST request has been reqested,
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        user = queries.get_user_from_name(username)

        # Check that email exists
        # and not attempting to login as admin
        if not user:
            flash('Invalid email or password', category='error')
            return redirect(url_for('login'))

        # Validate user password and store user session
        # also store the type of user
        if check_password_hash(user[6], password=password):
            session['user_id'] = user[0]
            session['user_type'] = user[4]
            session['user_fullname'] = (user[8], user[10])
            return redirect('/')
        else:
            flash('Invalid email or password', category='error')
            return redirect(url_for('login'))

        # update the user's last login
        queries.update_login_timestamp(username)

        return redirect(url_for('/'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register the user, before using account it must be activated"""

    if request.method == 'POST':

        user = {
            'now': datetime.datetime.now(),
            'access-level': 0,
            'username': request.form['username'],
            'hash': generate_password_hash(request.form['password']),
            'email': request.form['email'],
            'first-name': request.form['first-name'],
            'middle-name': request.form['middle-name'],
            'last-name': request.form['last-name'],
            'birthdate': helpers.get_date(request.form['birthdate']),
            'gender': request.form['gender'],
            'address1': request.form['address1'],
            'address2': request.form['address2'],
            'city': request.form['city'],
            'state': request.form['state'],
            'zip-code': request.form['zip-code'],
            'home-phone': request.form['home-phone'],
            'work-phone': request.form['work-phone'],
            'cell-phone': request.form['cell-phone']}

        confirm = request.form.get('confirm', None)

        # Check that user entered data correctly
        if not user['email'] or not user['hash'] or not confirm \
            or not user['first-name'] \
            or not user['last-name'] \
            or not user['gender'] \
            or not user['address1'] \
            or not user['city'] \
            or user['state'] == 'na' \
            or not user['birthdate'] \
            or not user['cell-phone']:
            flash('Required fields are missing', category='error')
            return redirect(url_for('register'))

        # Check that the passwords are identical
        if not check_password_hash(user['hash'], password=confirm):
            flash('Passwords don\'t match', category='error')
            return redirect(url_for('register'))

        # and accepted the terms
        elif not request.form['accept-terms']:
            flash('You must accept the terms', category='error')
            return redirect(url_for('register'))

        # Add user account to table
        queries.add_account(user)

        flash('Registration successful!', category='info')
        return redirect(url_for('login'))

    return render_template('register.html', us_states=helpers.states)

# Admin functions
# WARNING: Security risk, do not use in production environment
@app.route('/add_staff', methods=['GET', 'POST'])
def add_staff():

    if request.method == 'POST':

        username = request.form['username']

        user = {
            'now': datetime.datetime.now(),
            'access-level': 100 if request.form.get('admin', None) != None else 50,
            'username': username,
            'hash': generate_password_hash(request.form['password']),
            'email': f"{username}@emeraldvalleyclinic.edu",
            'first-name': request.form['first-name'],
            'middle-name': request.form['middle-name'],
            'last-name': request.form['last-name'],
            'birthdate': helpers.get_date(request.form['birthdate']),
            'gender': request.form['gender'],
            'address1': request.form['address1'],
            'address2': request.form['address2'],
            'city': request.form['city'],
            'state': request.form['state'],
            'zip-code': request.form['zip-code'],
            'home-phone': request.form['home-phone'],
            'work-phone': request.form['work-phone'],
            'cell-phone': request.form['cell-phone']}

        confirm = request.form['confirm']

         # Check that user entered data correctly
        if not user['email'] or not user['hash'] or not confirm \
            or not user['first-name'] \
            or not user['last-name'] \
            or not user['gender'] \
            or not user['address1'] \
            or not user['city'] \
            or user['state'] == 'na' \
            or not user['birthdate'] \
            or not user['cell-phone']:
            flash('Required fields are missing', category='error')
            return render_template('add_staff.html', us_states=helpers.states)

        # Check that the passwords are identical
        if not check_password_hash(user['hash'], password=confirm):
            flash('Passwords don\'t match', category='error')
            return render_template('add_staff.html', us_states=helpers.states)

        # Add user account to table
        queries.add_account(user)

        flash('User successfully added!', category='info')
        return redirect(url_for('login'))

    return render_template('add_staff.html', us_states=helpers.states)


@app.route('/assign_provider', methods=['GET', 'POST'])
@helpers.admin_required
def assign_provider():
    """
    Insert a row into provider_team table
    """

    patients = [(user[0], f'{user[2]}, {user[1]}') for user in queries.get_users_full_name_by_type(0)]
    providers = [(user[0], f'{user[2]}, {user[1]}') for user in queries.get_users_full_name_by_type(50)]

    if request.method == 'POST':

        patient_id = int(request.form['patient'])
        provider_id = int(request.form['provider'])

        if not patient_id or not provider_id:
            flash('Must include patient and provider', category='error')
            return redirect(url_for('assign_provider'))

        ans = queries.is_unique_provider(patient_id, provider_id)

        if not ans:
            flash('Provider already assigned to this patient', category='error')
            return redirect(url_for('assign_provider'))

        queries.assign_provider(patient_id, provider_id)

        flash('Patient successfully assigned.', category='info')
        return redirect(url_for('assign_provider'))

    return render_template('assign_provider.html', patients=patients, providers=providers)


@app.route('/logout')
def logout():
    """Log user out"""

    # Clear session
    session.clear()

    # Redirect to login
    return redirect(url_for('login'))


@app.route('/check', methods=['GET'])
def check():
    """
    Return true if an email is available
    """

    username = request.args.get('username', None)
    row = queries.get_user_from_name(username)

    return jsonify(row==None)


@app.errorhandler(400)
def bad_request(error):
    """
    Notify user the request was malformed and could not be understood by server.
    """
    return helpers.apology('bad request', 400)


@app.errorhandler(404)
def not_found_error(error):
    """
    Notify the user that this page could not be located.
    """
    return helpers.apology('not found', 404)


@app.errorhandler(500)
def internal_error(error):
    """
    Notify the user a problem has occured in the server
    """
    return helpers.apology('server error', 500)