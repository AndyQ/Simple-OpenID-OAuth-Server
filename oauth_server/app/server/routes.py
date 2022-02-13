import urllib.parse as urlparse
from flask import Flask, redirect, render_template, request, jsonify, flash
from urllib.parse import urlencode

from app import app
from app import user_management
from app import openid_management
from . import server

from .auth import (authenticate_client,
                  generate_access_and_refresh_tokens,
                  generate_jwt_token,
                  generate_authorization_code,
                  get_details_from_authorization_code,
                  verify_authorization_code, verify_client_info, verify_redirect_uri,
                  save_tokens, 
                  revokeToken, decode_auth_header, renewAccessToken,
                  get_details_for_access_token, getJWK, 
                  JWT_LIFE_SPAN)

from .users import authenticate_user_credentials



@server.route('/auth')
def auth():
    # Describe the access request of the client and ask user for approval
    client_id = request.args.get('client_id')
    redirect_url = request.args.get( 'redirect_url', request.args.get('redirect_uri'))
    scope = request.args.get('scope', "")
    state = request.args.get('state', "")
    nonce = request.args.get('nonce', "")

    if None in [client_id, redirect_url]:
        flash("Missing client_id or redirect_url")
        return jsonify({
            "error": "invalid_request - missing client_id or redirect_url"
        }), 400

    if not verify_client_info(client_id):
        flash("Invalid client_id")
        return jsonify({
            "error": "invalid_client_id"
        })

    if not verify_redirect_uri(client_id, redirect_url):
        flash("Invalid redirect_url")
        return jsonify({
            "error": "invalid_redirect_uri"
        })

    return render_template('grant_access.html',
                           client_id=client_id,
                           redirect_url=redirect_url,
                           scope=scope,
                           state=state,
                           nonce=nonce)


def process_redirect_url(redirect_url, authorization_code, state):
    # Prepare the redirect URL
    url_parts = list(urlparse.urlparse(redirect_url))
    queries = dict(urlparse.parse_qsl(url_parts[4]))
    queries.update({"code": authorization_code})
    queries.update({"state": state})
    url_parts[4] = urlencode(queries)
    url = urlparse.urlunparse(url_parts)
    return url


@server.route('/signin', methods=['POST'])
def signin():
    # Issues authorization code
    username = request.form.get('username')
    password = request.form.get('password')
    client_id = request.form.get('client_id')
    redirect_url = request.form.get('redirect_url')
    scope = request.form.get('scope', "")
    state = request.form.get('state', "")
    nonce = request.form.get('nonce', "")

    if None in [username, password, client_id, redirect_url]:
        flash("invalid_request - missing username, password, client_id or redirect_url")
        return render_template('grant_access.html',
                           client_id=client_id,
                           redirect_url=redirect_url,
                           username=username)

    if not verify_client_info(client_id):
        flash("Invalid client_id")
        return render_template('grant_access.html',
                    client_id=client_id,
                    redirect_url=redirect_url,
                    username=username)

    if not verify_redirect_uri(client_id, redirect_url):
        flash("Invalid redirect_url")
        return render_template('grant_access.html',
                    client_id=client_id,
                    redirect_url=redirect_url,
                    username=username)

    if not authenticate_user_credentials(username, password):
        flash("Invalid username or password")
        return render_template('grant_access.html',
                    client_id=client_id,
                    redirect_url=redirect_url,
                    username=username)

    authorization_code = generate_authorization_code(client_id, username, redirect_url, scope, nonce)

    url = process_redirect_url(redirect_url, authorization_code, state)

    return redirect(url, code=303)

@server.route('/token', methods=['POST'])
def exchange_for_token():
    # Issues access token
    authorization_code = request.form.get('code')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')

    # If there is an authorization header then this overrides the 
    # client_id and client_secret
    auth_header = request.headers.get('Authorization')
    if auth_header is not None:
        (client_id, client_secret) = decode_auth_header( auth_header ) 

    redirect_url = request.form.get(
        'redirect_url', request.form.get('redirect_uri'))

    if None in [authorization_code, client_id, client_secret, redirect_url]:
        return jsonify({
            "error": "invalid_request - missing data"
        }), 400

    if not authenticate_client(client_id, client_secret):
        return jsonify({
            "error": "invalid_client_id"
        }), 400

    auth_details = get_details_from_authorization_code(authorization_code)

    if not verify_authorization_code(authorization_code, client_id, redirect_url):
        return jsonify({
            "error": "access_denied"
        }), 400

    # Lookup user details
    user_id = auth_details['username']
    scope = auth_details['scope']
    nonce = auth_details['nonce']
    user_details = user_management.getUser(user_id)
    (access_token, refresh_token) = generate_access_and_refresh_tokens()

    id_token = None

    # Store access and refresh tokens against userid
    save_tokens(user_id, client_id, scope, access_token, refresh_token )

    ret = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": JWT_LIFE_SPAN,
        'refresh_expires_in': 2592000
    }
    if "openid" in scope:
        id_token = generate_jwt_token(client_id, user_details, scope, nonce)
        ret["id_token"] = id_token

    return jsonify(ret)

@server.route('/revoke', methods=['POST'])
def revokeAccessToken():
    token = request.form.get('token')
    client_id = request.form.get('client_id')

    if not verify_client_info(client_id):
        return jsonify({
            "error": "invalid_client"
        })

    revokeToken(token)

    return "OK"

@server.route('/introspect', methods=['POST'])
def introspect():
    token = request.form.get('token')

    tokenDetails = get_details_for_access_token( token )
    if tokenDetails == None:
        return jsonify({
            "error": "invalid_request"
        }), 400

    user_id = tokenDetails["user_id"]
    client_id = tokenDetails["client_id"]
    scope = tokenDetails["scope"]
    user = user_management.getUser(user_id)
    openIDConfig = openid_management.loadConfig()

    resp = {
            'sub': user_id, 
            'aud': client_id, 
            'scope': scope,
            'active': True, 
            'scope': scope,
            'iairgroup.attributes': {}, 
            'client_id': client_id 
    }

    if openIDConfig.get("includeRoles", False) == True and openIDConfig.get("roleClaimName", "") != "":
        resp[openIDConfig["roleClaimName"]] = user.get("permissions", {}).get(client_id, [])
    return jsonify(resp)
            #'iairgroup.roles': ['IAGStore.Admin_BADEV', 'IAGStore.Admin_BAPOC', 'IAGStore.Admin_IAGStore', 'IAGStore.Develop_IAGStore']

@server.route('/certs', methods=['GET'])
def certs():
    jwk = getJWK()
    return jsonify(jwk)


if __name__ == '__main__':
    #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    #context.load_cert_chain('domain.crt', 'domain.key')
    #app.run(port = 5000, debug = True, ssl_context = context)
    app.run(port=8001, debug=True)
