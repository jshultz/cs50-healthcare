import sqlite3
import datetime

import helpers

SQL_DATABASE_URL = 'clinic.db'

def add_account(user):

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    # user id number to insert
    with conn:
        c.execute('INSERT INTO users (' + \
            'id, ' + \
            'ts_created, ' + \
            'ts_modified, ' + \
            'ts_lastlogin, ' + \
            'access_level, ' + \
            'username, ' + \
            'hash, ' + \
            'email, ' + \
            'first_name, ' + \
            'middle_name, ' + \
            'last_name, ' + \
            'birthdate, ' + \
            'gender, ' + \
            'address1, ' + \
            'address2, ' + \
            'city, ' + \
            'state, ' + \
            'zip_code, ' + \
            'home_phone, ' + \
            'work_phone, ' + \
            'cell_phone) VALUES (' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?, ' + \
            '?)', (
            None,
            user['now'],
            user['now'],
            user['now'],
            user['access-level'],
            user['username'],
            user['hash'],
            user['email'],
            user['first-name'],
            user['middle-name'],
            user['last-name'],
            user['birthdate'],
            user['gender'],
            user['address1'],
            user['address2'],
            user['city'],
            user['state'],
            user['zip-code'],
            user['home-phone'],
            user['work-phone'],
            user['cell-phone'],))

    c.close()


def get_user_from_name(username):

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute('SELECT * ' + \
        'FROM users ' + \
        'WHERE username=?',
        (username,))

    user = rows.fetchone() if rows.rowcount != 0 else []

    conn.close()

    return user

def get_user_from_id(user_id):

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute("SELECT * " + \
        "FROM users " + \
        "WHERE id=?",
        (user_id,))

    user = rows.fetchone() if rows.rowcount != 0 else []

    conn.close()

    return user


def update_login_timestamp(username):
    """
    called on login updates the last login for the user
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute('UPDATE users SET ts_lastlogin = ? WHERE username = ?',
        (datetime.datetime.now(), username,))

    c.close()


def post_message(meta):
    """
    insert a new row into messages table
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute('INSERT INTO messages (' + \
        'id, ' + \
        'ts_sent, ' + \
        'unread, ' + \
        'archived, ' + \
        'priority, ' + \
        'subject, ' + \
        'body, ' + \
        'sender, ' + \
        'receiver) VALUES (' + \
        '?,' + \
        '?,' + \
        '?,' + \
        '?,' + \
        '?,' + \
        '?,' + \
        '?,' + \
        '?,' + \
        '?)',
        (None,
        datetime.datetime.now(),
        True,
        False,
        meta['priority'],
        meta['subject'],
        meta['body'],
        meta['sender'],
        meta['receiver']))

    conn.close()


def broadcast(users, message):
    """
    Send a message to all users
    """

    for user in users:
        post_message({
            'sender': message['sender'],
            'receiver': user,
            'priority': message['priority'],
            'subject': message['subject'],
            'body': message['body']
        })


def get_messages(user_id, archived=False):
    """
    Fetch all messages for this user
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute("SELECT messages.id, ts_sent, unread, priority, archived, sender, receiver, subject, body, users.access_level, users.first_name, users.last_name FROM messages " + \
        "INNER JOIN users ON (users.id == messages.sender) " + \
        "WHERE receiver = ? AND archived=?",
        (user_id, 0 if not archived else 1,))

    messages = rows.fetchall()
    conn.close()

    return messages


def get_message(message_id):
    """
    Fetch message
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        row = c.execute("SELECT messages.id, sender, receiver, subject, users.first_name, users.last_name FROM messages " + \
        "INNER JOIN users ON (users.id == messages.sender) " + \
        "WHERE messages.id = ?",
        (message_id,))

    message = row.fetchone()
    conn.close()

    return message


def mark_message(message_id, unread):
    """
    Mark a message, for read or unread
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute("UPDATE messages SET unread ? WHERE id = ?", (unread, message_id,))

    conn.close()


def archive_message(message_id):
    """
    Archives a message
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute("UPDATE messages SET archive = ? WHERE id = ?", (True, message_id,))

    conn.close()


def delete_message(message_id):
    """
    Delete a message
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute("DELETE FROM messsages WHERE id = ?", (message_id,))

    conn.close()


def reset_password(email, new_password):

    """
    Update the password for the selected user
    """
    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute('UPDATE users SET hash = ? WHERE email = ?',
        (new_password, email,))

    conn.close()


def is_unique_provider(patient_id, provider_id):
    """
    Return false if patient has been essigned this provider, else true
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute('SELECT patient_id, ' + \
        'provider_id ' + \
        'FROM provider_team ' + \
        'WHERE patient_id=? AND provider_id=?',
        (patient_id, provider_id,))

    res = True if len(rows.fetchall()) == 0 else False

    conn.close()

    return res


def assign_provider(patient_id, provider_id):
    """
    Inserts a new row with patient and provider,
    modeling a many:many relationship
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        c.execute('INSERT INTO provider_team (' + \
            'id, ' + \
            'patient_id, ' + \
            'provider_id) VALUES (?, ?, ?)',
            (None, patient_id, provider_id,))

    conn.close()


def get_patient_providers(patient_id):
    """
    Return the providers for this patient.
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute('SELECT patient_id, first_name, last_name, ' + \
        'FROM users ' + \
        'INNER JOIN provider_team ON (users.id == provider_team.patient_id) ' + \
        'WHERE users.id == ?',
        (patient_id,))

        providers = rows.fetchall()

    conn.close()

    return providers


def get_provider_patients(provider_id):
    """
    Return the patients assigned to this provider
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute('SELECT provider_id, first_name, last_name ' + \
        'FROM users ' + \
        'INNER JOIN provider_team ON (users.id == provider_team.provider_id) ' + \
        'WHERE users.id == ?',
        (provider_id,))

        patients = rows.fetchall()

    conn.close()

    return patients


def get_users_full_name_by_type(access_level):
    """
    Return users with the given access level
    0 = patients, 50 = clinical staff, 100 = administrator
    """

    conn = sqlite3.connect(SQL_DATABASE_URL)
    c = conn.cursor()

    with conn:
        rows = c.execute('SELECT id, ' + \
        'first_name, ' + \
        'last_name ' + \
        'FROM users WHERE access_level=?',
        (access_level,))

    users = rows.fetchall()

    conn.close()

    return users