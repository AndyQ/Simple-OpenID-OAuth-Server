oauth_server/config.py import os
from logging.config import dictConfig

from jwcrypto.jwk import JWK
from app import app

app.config['SESSION_TYPE'] = 'filesystem'
app.config['ENV'] = 'development'
app.config['DEBUG'] = True

# Logging Config
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

# App Config
hostname = os.getenv('HOST_URL', 'http://192.168.1.87:8001')
token_validity = os.getenv('TOKEN_VALIDITY_SECONDS', 3600)
jwk = JWK.generate(
    kty='RSA',
    size=2048,
    kid='fake-oidc',
    use='sig',
    alg='RS256'
)
