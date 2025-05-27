import requests

from logging.config import dictConfig

def getConfiguration():
    from app import app
    
    app.secret_key = 'super secret client app key'
    # app.config['SESSION_TYPE'] = 'filesystem'
    app.config['ENV'] = 'development'
    app.config['DEBUG'] = True

    # configure from OAuth Server lookup
    OAUTH_SERVER_HOST = 'http://localhost:8001'


    lookup = f"{OAUTH_SERVER_HOST}/.well-known/openid-configuration"
    resp = requests.get(lookup)
    respJson = resp.json()

    app.config['AUTH_PATH_URL'] = respJson['authorization_endpoint']
    app.config['TOKEN_PATH_URL'] = respJson['token_endpoint']
    app.config['END_SESSION_URL'] = respJson['end_session_endpoint']
    app.config['JWKS_CERTS_URL'] = respJson['jwks_uri']
    app.config['USER_INFO_URL'] = respJson['userinfo_endpoint']
