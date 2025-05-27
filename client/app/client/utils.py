from jwcrypto import jwt, jwk
import os
import requests
import json

from app import app

ISSUER = 'sample-auth-server'
AUDIENCE = "sample-client-id"

def extractJWT( token ):

    # Grab certs from oauth server
    resp = requests.get( app.config['JWKS_CERTS_URL'] )
    jsonResp = resp.json()

    str = jsonResp['keys'][0]

    key = jwk.JWK(**str)

    ET = jwt.JWT(key=key, jwt=token)
    claims = json.loads(ET.claims)

    header = ET.header

    return ( header, claims )


def save_cookie( response, name, value ):
    # TODO: Encrypt cookie value
    response.set_cookie(name, value)

def get_cookie( request, name ):
    # TODO: Decrypt cookie value
    value = request.cookies.get(name)
    return value


def generate_state():
    import random
    import string
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))

def generate_nonce():
    import random
    import string
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))