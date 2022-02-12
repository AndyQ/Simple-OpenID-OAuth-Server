from flask import Flask

################
#### config ####
################
 
app = Flask(__name__, instance_relative_config=True)

from .client import client

app.register_blueprint(client, url_prefix='/')
