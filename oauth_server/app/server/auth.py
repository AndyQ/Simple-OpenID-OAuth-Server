from base64 import b64decode, b64encode
import json
import os
import jwt
import uuid
import time
import struct
import hashlib
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from app import app
from app import app_management
from app import openid_management


# KEY = Fernet.generate_key()
KEY = b'YHD1m3rq3K-x6RxT1MtuGzvyLz4EWIJAEkRtBRycDHA='

ISSUER = 'sample-auth-server'
AUDIENCE = "iagstore"

CODE_LIFE_SPAN = 600
JWT_LIFE_SPAN = 1800  # 30 mins
ACCESS_LIFE_SPAN = 3600  # 60 mins
REFRESH_LIFE_SPAN = 2592000  # 30 days

authorization_codes = {}
access_tokens = []

f = Fernet(KEY)

class DecodeError(Exception):
    pass

private_key_pem = os.path.join(app.instance_path, 'private.pem')
with open(private_key_pem, 'rb') as file:
    private_key = file.read()
public_key_pem = os.path.join(app.instance_path, 'public.pem')
with open(public_key_pem, 'rb') as file:
    public_key = file.read()


def authenticate_client(client_id, client_secret):

    app = app_management.getApp( client_id )
    if app != None:
        if client_secret == app["secret"]:
            return True
    return False

def verify_client_info(client_id):

    app = app_management.getApp( client_id )
    if app != None:
        return True
    return False


def verify_redirect_uri(client_id, redirect_uri):
    app = app_management.getApp( client_id )
    if app != None:
        if redirect_uri == app["callback"]:
            return True


def generate_access_and_refresh_tokens():
    access = uuid.uuid4().hex
    refresh = uuid.uuid4().hex

    return (access, refresh)


def getPublicKeyKID():
    hash = hashlib.md5(public_key)
    kid = hash.hexdigest()
    return kid


def getJWK():
    pubkey = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )

    public_numbers = pubkey.public_numbers()

    jwk = {
        "alg": "RS256",
        "e": None,
        "n": None,
        "kid": getPublicKeyKID(),
        "kty": "RSA",
        "use": "sig"
    }

    jwk['n'] = long_to_base64(public_numbers.n)
    jwk['e'] = long_to_base64(public_numbers.e)

    print(jwk)

    return jwk


def long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n):
    bys = long2intarr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")


def generate_jwt_token(client_id, user, scopes, nonce):

    # Bring in OpenID Settings
    openIDConfig = openid_management.loadConfig()

    # standard claims
    payload = {
        "iss": ISSUER,
        "exp": time.time() + JWT_LIFE_SPAN,
        "aud": client_id,
        "sub": user["email"],
        "iat": time.time()
    }

    if  nonce != "":
        payload["nonce"] = nonce

    for claim in openIDConfig["claims"]:
        claimName = claim
        # handle special cases first
        if claimName == "name":
            payload[claimName] = user["given_name"] + " " + user["family_name"]
        elif claimName == "email_verified":
            payload[claimName] = False
        elif claimName == "phone_number_verified":
            payload[claimName] = False
        elif claimName == "updated_at":
            payload[claimName] = user["name"]
        else:
            if user.get( claimName, "" ) != "":
                payload[claimName] = user[claimName]

    if openIDConfig["includeRoles"] and openIDConfig.get("roleClaimName", "") != "":
        payload[openIDConfig["roleClaimName"]] = user.get("permissions", {}).get(client_id, [])

    access_token = jwt.encode(payload, private_key, algorithm='RS256', headers={
                              'kid': getPublicKeyKID()})

    return access_token


def generate_authorization_code(client_id, username, redirect_url, scope, nonce):
    # f = Fernet(KEY)
    authorization_code = f.encrypt(json.dumps({
        "client_id": client_id,
        "username": username,
        "redirect_url": redirect_url,
        "scope": scope,
    }).encode())

    authorization_code = base64.b64encode(
        authorization_code, b'-_').decode().replace('=', '')

    expiration_date = time.time() + CODE_LIFE_SPAN

    authorization_codes[authorization_code] = {
        "client_id": client_id,
        "username": username,
        "redirect_url": redirect_url,
        "exp": expiration_date,
        "scope": scope,
        "nonce": nonce,
    }

    return authorization_code


def get_details_from_authorization_code( authorization_code ):
    record = authorization_codes.get(authorization_code)
    if not record:
        return None

    return record

def verify_authorization_code(authorization_code, client_id, redirect_url):
    # f = Fernet(KEY)
    record = authorization_codes.get(authorization_code)
    if not record:
        return False

    client_id_in_record = record.get('client_id')
    redirect_url_in_record = record.get('redirect_url')
    exp = record.get('exp')

    if client_id != client_id_in_record or \
       redirect_url != redirect_url_in_record:
        return False

    if exp < time.time():
        return False

    del authorization_codes[authorization_code]

    return True


def save_tokens(user_id, client_id, scope, access_token, refresh_token):
    access_tokens.append({
        "user_id": user_id,
        "client_id": client_id,
        "scope": scope,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_expiry": time.time() + ACCESS_LIFE_SPAN,
        "refresh_expiry": time.time() + REFRESH_LIFE_SPAN
    })


def revokeToken(access_token):
    for t in access_tokens:
        if t["access_token"] == token:
            access_tokens.remove(t)
            return True
    return False


def verify_access_token(token):
    for t in access_tokens:
        if t["access_token"] == token:
            if t["access_expiry"] > time.time():
                return t

            return None
    return None


def verify_refresh_token(token):
    for t in access_tokens:
        if t["refresh_token"] == token:
            if t["refresh_expiry"] > time.time():
                return t
            return False
    return False


def get_details_for_access_token(token):
    t = verify_access_token(token)
    if t != None:
        return t
    return None


def renewAccessToken(refreshToken):
    for t in access_tokens:
        if t["refresh_token"] == refreshToken and t["refresh_expiry"] > time.time():
            access_token = uuid.uuid4().hex
            refresh_token = uuid.uuid4().hex
            t["access_token"] = access_token
            t["refresh_token"] = refresh_token
            t["access_expiry"] = time.time() + ACCESS_LIFE_SPAN
            t["refresh_expiry"] = time.time() + REFRESH_LIFE_SPAN

            return (access_token, refresh_token)
    return None


def decode_auth_header(encoded_str):
    """Decode an encrypted HTTP basic authentication string. Returns a tuple of
    the form (username, password), and raises a DecodeError exception if
    nothing could be decoded.
    """
    split = encoded_str.strip().split(' ')

    # If split is only one element, try to decode the username and password
    # directly.
    if len(split) == 1:
        try:
            username, password = b64decode(split[0]).decode().split(':', 1)
        except:
            raise DecodeError

    # If there are only two elements, check the first and ensure it says
    # 'basic' so that we know we're about to decode the right thing. If not,
    # bail out.
    elif len(split) == 2:
        if split[0].strip().lower() == 'basic':
            try:
                username, password = b64decode(split[1]).decode().split(':', 1)
            except:
                raise DecodeError
        else:
            raise DecodeError

    # If there are more than 2 elements, something crazy must be happening.
    # Bail.
    else:
        raise DecodeError

    return username, password
