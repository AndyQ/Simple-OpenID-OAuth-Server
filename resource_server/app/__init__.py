from flask import Flask

################
#### config ####
################
 
app = Flask(__name__, instance_relative_config=True)

from .resource import resource

app.register_blueprint(resource, url_prefix='/')
