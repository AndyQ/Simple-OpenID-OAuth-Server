import os
import json

from app import app

def getListOfApps():
    appsFile = os.path.join(app.instance_path, 'data/apps.json')
    with open( appsFile, "r" ) as f:
        apps = json.load( f )
    return apps

def saveApps( apps ):
    appsFile = os.path.join(app.instance_path, 'data/apps.json')
    with open( appsFile, "w" ) as f:
        json.dump( apps, f, indent=4 )

def getApp( app_id ):
    apps = getListOfApps()

    apps = [app for app in apps if (app['app_id'] == app_id)]

    if len(apps) > 0:
        return apps[0]
    return None

def addOrUpdateApp( originalapp_id, app ):
    apps = getListOfApps()

    # Remove old app from list
    if originalapp_id != "":
        apps = [app for app in apps if not (app['app_id'] == originalapp_id)]
    apps.append( app )

    saveApps(apps)

def deleteApp( app_id ):
    apps = getListOfApps()

    apps = [app for app in apps if not (app['app_id'] == app_id)]

    saveApps(apps)

