import jwt
import os

from app import app

public_key_pem = os.path.join(app.instance_path, 'public.pem')
with open(public_key_pem, 'rb') as file:
    public_key = file.read()

ISSUER = 'sample-auth-server'
AUDIENCE = "sample-client-id"

def extractJWT( token ):

    claims = jwt.decode(token, public_key,
                            issuer = ISSUER,
                            audience = AUDIENCE,
                            algorithms = ['RS256'])

    header = jwt.get_unverified_header(token)

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