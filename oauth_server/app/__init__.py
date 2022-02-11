from flask import Flask

################
#### config ####
################
 
app = Flask(__name__, instance_relative_config=True)

from .server import server
from .admin import admin

app.register_blueprint(server, url_prefix='/')
app.register_blueprint(admin, url_prefix='/admin')
