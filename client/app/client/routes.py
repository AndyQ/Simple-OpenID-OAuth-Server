import json
import requests

from flask import (Flask, make_response, render_template, redirect, request,
                   url_for, flash)

from . import client
from . import utils

AUTH_PATH = 'http://localhost:8001/auth'
TOKEN_PATH = 'http://localhost:8001/token'
REDIRECT_URL = 'http://localhost:8000/callback'
RES_PATH = 'http://localhost:8002/users'

CLIENT_ID = 'sample-client-id'
CLIENT_SECRET = 'sample-client-secret'

app = Flask(__name__)


@client.before_request
def before_request():
    # Redirects user to the login page if access token is not present
    if request.endpoint not in ['client.login', 'client.callback', 'client.logout']:
        access_token = request.cookies.get('access_token')
        if access_token:
            pass
        else:
            return redirect(url_for('client.login'))


@client.route('/')
def main():
    return render_template('client/logged_in.html')

@client.route('/viewAuthDetails')
def viewAuthDetails():
    auth_details = request.cookies.get('auth_details')
    id_token = request.cookies.get('id_token')
    (header, claims) = utils.extractJWT( id_token )

    # Pretty print json
    auth_details = json.dumps(json.loads(auth_details), indent=4, sort_keys=True)
    header = json.dumps(header, indent=4, sort_keys=True)
    claims = json.dumps(claims, indent=4, sort_keys=True)

    return render_template('client/view_auth_details.html', auth_details=auth_details, jwt_header=header, jwt_claims=claims)

@client.route('/getUsers')
def getUsers():
    # Retrieves a list of users
    access_token = request.cookies.get('access_token')

    r = requests.get(RES_PATH, headers={
        'Authorization': 'Bearer {}'.format(access_token)
    })

    if r.status_code != 200:
        if r.status_code == 401:
            # Invalid token, logout user
            flash('Your session has expired, please login again.')
            return redirect(url_for('client.logout'))

        flash(f'The resource server returned an error:<br>{r.text}')
        return redirect(url_for('client.main'))

    users = json.loads(r.text).get('results')

    return render_template('client/users.html', users=users)


@client.route('/login', methods=['GET', 'POST'])
def login():

    
    if request.method == "POST":
        auth_url = f"{AUTH_PATH}?response_type=code&client_id={CLIENT_ID}&redirect_url={REDIRECT_URL}&scope=openid"
        return redirect(auth_url)

    # Presents the login page
    return render_template('client/login.html' )


@client.route('/logout')
def logout():
    # Presents the login page
    response = make_response(render_template('client/logout.html' ))

    response.set_cookie('auth_details', '', expires=0)
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    response.set_cookie('id_token', '', expires=0)

    return response


@client.route('/callback')
def callback():
    # Accepts the authorization code and exchanges it for access token
    authorization_code = request.args.get('code')

    if not authorization_code:
        return json.dumps({
            'error': 'No authorization code is received.'
        }), 500

    r = requests.post(TOKEN_PATH, data={
        "grant_type": "authorization_code",
        "code": authorization_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_url": REDIRECT_URL
    })

    if r.status_code != 200:
        return json.dumps({
            'error': 'The authorization server returns an error: \n{}'.format(
                r.text)
        }), 500

    auth_details = r.text
    auth = json.loads(auth_details)

    access_token = auth.get('access_token')
    refresh_token = auth.get('refresh_token')
    id_token = auth.get('id_token')

    response = make_response(redirect(url_for('client.main')))

    # Don't do this - ideally these should be stored in a server side session
    # or encrypted BUT as this is a test app - you may want to see client side
    response.set_cookie('auth_details', auth_details)
    response.set_cookie('access_token', access_token)
    response.set_cookie('refresh_token', refresh_token)
    response.set_cookie('id_token', id_token)
    return response
