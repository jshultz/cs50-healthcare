from flask import render_template, redirect, session, url_for

from string import ascii_uppercase, digits
from secrets import randbelow

import queries

import datetime

from functools import wraps

states = [
    {'ak': 'Alaska'},
    {'al': 'Alabama'},
    {'ar': 'Arkansas'},
    {'az': 'Arizona'},
    {'ca': 'California'},
    {'co': 'Colorado'},
    {'ct': 'Connecticut'},
    {'dc': 'District of Columbia'},
    {'de': 'Delaware'},
    {'fl': 'Florida'},
    {'ga': 'Georgia'},
    {'hi': 'Hawaii'},
    {'ia': 'Iowa'},
    {'id': 'Idaho'},
    {'il': 'Illinois'},
    {'in': 'Indiana'},
    {'ks': 'Kansas'},
    {'ky': 'Kentucky'},
    {'la': 'Louisiana'},
    {'ma': 'Massachusetts'},
    {'md': 'Maryland'},
    {'me': 'Maine'},
    {'mi': 'Michigan'},
    {'mn': 'Minnesota'},
    {'mo': 'Missouri'},
    {'ms': 'Mississippi'},
    {'mt': 'Montana'},
    {'nc': 'North Carolina'},
    {'nd': 'North Dakota'},
    {'ne': 'Nebraska'},
    {'nh': 'New Hampshire'},
    {'nj': 'New Jersey'},
    {'nm': 'New Mexico'},
    {'nv': 'Nevada'},
    {'ny': 'New York'},
    {'oh': 'Ohio'},
    {'ok': 'Oklahoma'},
    {'or': 'Oregon'},
    {'pa': 'Pennsylvania'},
    {'ri': 'Rhode Island'},
    {'sc': 'South Carolina'},
    {'sd': 'South Dakota'},
    {'tn': 'Tennessee'},
    {'tx': 'Texas'},
    {'ut': 'Utah'},
    {'va': 'Virginia'},
    {'vt': 'Vermont'},
    {'wa': 'Washington'},
    {'wi': 'Wisconsin'},
    {'wv': 'West Virginia'},
    {'wy': 'Wyoming'}]

def get_state(abb):

    # define a dict that will be used to find the state selected by user
    states_dict = dict()

    # build a dictionary from states, an array-dict
    for i in states:
        states_dict.update(i)

    return states_dict[abb]


def apology(message, code=400):
    """
    Report to the user what happened with a meme
    """

    def escape(s):
        """Escapes special characters"""

        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message))


def get_date(date_str):
    """
    Create a date object from string format: YYYY-mm-dd
    """

    date_str = date_str if date_str != '' else '1900-1-1'

    date_split = [int(x) for x in date_str.rsplit('-')]

    return datetime.date(date_split[0], date_split[1], date_split[2])


def login_required(f):
    """
    Decorate routes to require login.
    redirects to login page if no session exists
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


def staff_required(f):
    """
    Decorate routes to require a staff (doctor or nurse)
    redirect
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or session['user_type'] != 50:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorate routes to require administrator login
    redirects to default route if administrator
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or session['user_type'] != 100:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function