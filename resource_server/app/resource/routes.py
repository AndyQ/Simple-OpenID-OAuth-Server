import json
# import ssl
from functools import wraps

from flask import Flask, request, jsonify

from . import resource
from . import auth

app = Flask(__name__)


def check_auth(f):
    @wraps(f)
    def wrap(*args, **kwargs):

        # Checks if the access token is present and valid.
        auth_header = request.headers.get('Authorization')
        if 'Bearer' not in auth_header:
            return jsonify({
            'error': 'Access token does not exist.'
            }), 401

        access_token = auth_header[7:]

        if access_token:
            userInfo = auth.verify_access_token(access_token)
            if userInfo != None:
                kwargs["user_details"] = userInfo
                return f(*args, **kwargs)

        return jsonify({
        'error': 'Access token is invalid.'
        }), 401

    return wrap


#@resource.before_request
def before_request():
    # Checks if the access token is present and valid.
    auth_header = request.headers.get('Authorization')
    if 'Bearer' not in auth_header:
        return json.dumps({
        'error': 'Access token does not exist.'
        }), 401

    access_token = auth_header[7:]

    if access_token and auth.verify_access_token(access_token):
        pass
    else:
        return json.dumps({
        'error': 'Access token is invalid.'
        }), 401


@resource.route('/users', methods=['GET'])
@check_auth
def get_user(user_details):
  # Returns a list of users.

    if "User" in user_details["roles"]:
        return jsonify({
        'error': 'User is not authorized to access this resource.'
        }), 403

    users = [
        { 'username': 'bob', 'email': 'bob@example.com'},
        { 'username': 'John Doe', 'email': 'johndoe@example.com'}
    ]

    return json.dumps({
        'results': users
    })
