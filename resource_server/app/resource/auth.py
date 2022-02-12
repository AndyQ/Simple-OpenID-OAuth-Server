import jwt
import requests
import os
from app import app

ISSUER = 'sample-auth-server'
AUDIENCE = "sample-client-id"

public_key_pem = os.path.join(app.instance_path, 'public.pem')
with open(public_key_pem, 'rb') as file:
    public_key = file.read()


def verify_access_token(access_token):
    # see if its A JWT and we can verify it
    try:
        decoded_token = jwt.decode(access_token, public_key,
                                   issuer=ISSUER,
                                   audience=AUDIENCE,
                                   algorithms=['RS256'])

        print( decoded_token )
        return decoded_token
    except (jwt.exceptions.InvalidTokenError,
            jwt.exceptions.InvalidSignatureError,
            jwt.exceptions.InvalidIssuerError,
            jwt.exceptions.ExpiredSignatureError) as e:

        # probably not so call the introspection service 
        # and try to verify it there
        r = requests.post(f"http://localhost:8001/introspect",  data={'token': access_token})
        if r.status_code == 200:
            resp = r.json()

            print(resp)
            # ensure that the token is active and the audience matches
            if resp['active'] and resp['aud'] == AUDIENCE:
                return resp

    return None
