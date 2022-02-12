import os
import json

from app import app

def loadConfig():
    appsFile = os.path.join(app.instance_path, 'data/openid.json')
    with open( appsFile, "r" ) as f:
        apps = json.load( f )
    return apps

def saveConfig( openidConfig ):
    appsFile = os.path.join(app.instance_path, 'data/openid.json')
    with open( appsFile, "w" ) as f:
        json.dump( openidConfig, f, indent=4 )

def getClaims():
    openidConfig = loadConfig()
    return openidConfig['claims']