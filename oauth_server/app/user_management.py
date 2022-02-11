import os
import json
import hashlib
import hmac
from base64 import b64decode, b64encode

from app import app

def getListOfUsers():
    usersFile = os.path.join(app.instance_path, 'data/users.json')
    with open( usersFile, "r" ) as f:
        users = json.load( f )
    return users

def saveUsers( users ):
    usersFile = os.path.join(app.instance_path, 'data/users.json')
    with open( usersFile, "w" ) as f:
        json.dump( users, f, indent=4 )

def getUser( user_id ):
    users = getListOfUsers()

    users = [user for user in users if (user['user_id'] == user_id)]
    if len(users) > 0:
        return users[0]
    return None

def addOrUpdateUser( original_user_id, new_user ):
    users = getListOfUsers()

    # Remove old app from list
    if original_user_id != "":
        users = [user for user in users if not (user['user_id'] == original_user_id)]
    users.append( new_user )

    saveUsers(users)

def deleteUser( user_id ):
    users = getListOfUsers()

    users = [user for user in users if not (user['user_id'] == user_id)]

    saveUsers(users)

def hash_new_password(password):
    """
    Hash the provided password with a randomly-generated salt and return the
    salt and hash to store in the database.
    """
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return b64encode(salt).decode(), b64encode(pw_hash).decode()

def is_correct_password(salt_b64, pw_hash_b64, password):
    """
    Given a previously-stored salt and hash, and a password provided by a user
    trying to log in, check whether the password is correct.
    """

    salt = b64decode(salt_b64)
    pw_hash = b64decode(pw_hash_b64)

    return hmac.compare_digest(
        pw_hash,
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    )
