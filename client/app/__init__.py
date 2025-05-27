from flask import Flask
import config

################
#### config ####
################
 
app = Flask(__name__, instance_relative_config=True)

config.getConfiguration()

from .client import client

app.register_blueprint(client, url_prefix='/')
