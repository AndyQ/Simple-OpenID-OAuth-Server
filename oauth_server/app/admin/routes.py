import os
import json

from flask   import redirect, render_template, request, url_for, jsonify
from app import app, app_management, user_management, openid_management
from . import admin


# App main route + generic routing
@admin.route('/')
def index():

    apps = app_management.getListOfApps()
    users = user_management.getListOfUsers()

    context = { "nrApps" : len(apps), "nrUsers" : len(users) }
    return render_template('admin/index.html', **context)


# USERS
@admin.route('/apps')
def viewApps():

    # get list of apps
    apps = app_management.getListOfApps()

    context = { "apps" : apps}
    return render_template( 'admin/apps.html', **context)

@admin.route('/appRoles/<app_id>')
def appRoles(app_id):

    # get list of apps
    app = app_management.getApp(app_id)
    return jsonify(app["roles"] )

@admin.route('/editapp', methods=['GET', 'POST'])
def editApp():

    if request.method == "GET":
        app_id = request.args.get('app_id')

        app = app_management.getApp( app_id )
        context = { "app" : app}

        return render_template('admin/editCreateApp.html', **context)
    else:
        app = {}
        originalapp_id = request.form.get('originalapp_id')
        app["app_id"] = request.form.get('app_id')
        app["description"] = request.form.get('appDesc')
        app["secret"] = request.form.get('appSecret')
        app["callback"] = request.form.get('appCallback')
        app["roles"] = request.form.get('roles').split(',')

        # save app
        app_management.addOrUpdateApp( originalapp_id, app )
    return redirect( url_for( 'admin.viewApps' ) )

@admin.route('/deleteapp')
def deleteApp():
    app_idToDelete = request.args.get('app_id')

    # get list of apps
    app_management.deleteApp( app_idToDelete )

    return redirect( url_for( 'admin.viewApps' ) )

# Users
@admin.route('/users')
def viewUsers():

    # get list of apps
    users = user_management.getListOfUsers()

    context = { "users" : users}
    return render_template( 'admin/users.html', **context)

@admin.route('/edituser', methods=['GET', 'POST'])
def editUser():

    openIDConfig = openid_management.loadConfig()
    if request.method == "GET":
        user_id = request.args.get('user_id')

        user = user_management.getUser( user_id )
        apps = app_management.getListOfApps()

        appNames = [app["app_id"] for app in apps]

        context = { "user" : user,
                    "appNames" : appNames,
                    "availableClaims" : openIDConfig["availableClaims"]
        }

        return render_template('admin/editCreateUser.html', **context)
    else:
        original_user_id = request.form.get('original_user_id')
        user = user_management.getUser( original_user_id )
        new_user = False
        if user == None:
            user = {}
            new_user = True

        # First handle password
        password = request.form.get('password')
        if password == None or password != "":
            (salt, pw_hash) = user_management.hash_new_password( password )
            user["password_salt"] = salt
            user["password_hash"] = pw_hash
        elif new_user == True:
            context = { "user" : user, "error": "You must set a password"}
            return render_template('admin/editCreateUser.html', **context)
        user["user_id"] = request.form.get('user_id')

        # now add up the available claims
        for claim in openIDConfig["availableClaims"]:
            if claim["name"] in request.form:
                user[claim["name"]] = request.form.get(claim["name"])

        # user["given_name"] = request.form.get('given_name')
        # user["family_name"] = request.form.get('family_name')
        # user["email"] = request.form.get('email')

        # handle roles - its a string of , separated app_ids:role
        roles = request.form.get('roles').split(",")
        user["permissions"] = {}
        for role in roles:
            app_id = role.split(":")[0]
            role = role.split(":")[1]

            if app_id not in user["permissions"]:
                user["permissions"][app_id] = []
            user["permissions"][app_id].append(role)

        # save user
        user_management.addOrUpdateUser( original_user_id, user )
    return redirect( url_for( 'admin.viewUsers' ) )

@admin.route('/deleteuser')
def deleteUser():
    user_id_to_delete = request.args.get('user_id')

    # get list of apps
    user_management.deleteUser( user_id_to_delete )

    return redirect( url_for( 'admin.viewUsers' ) )


# OpenID Connect

@admin.route('/openid', methods=['GET', 'POST'])
def openid():

    openIDDetails = openid_management.loadConfig()

    if request.method == "POST":
        openIDClaims = []
        for claim in claims:
            val = request.form.get(claim[0])
            if val != None:
                openIDClaims.append( claim[0] )

        openIDDetails["claims"] = openIDClaims
        if request.form.get( "includeRoles" ):
            roleName = request.form.get( "roleName", "role" )

            openIDDetails["includeRoles"] = True
            openIDDetails["roleClaimName"] = roleName
        else:
            openIDDetails["includeRoles"] = False

        # save openID Claim Details
        openid_management.saveConfig( openIDDetails )

    context = { "availableClaims": openIDDetails["availableClaims"], 
                "claims" : openIDDetails["claims"],
                "includeRoles" : openIDDetails["includeRoles"],
                "roleClaimName" : openIDDetails["roleClaimName"] }
    return render_template( 'admin/openid.html', **context)
