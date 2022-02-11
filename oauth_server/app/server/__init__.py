from flask import Blueprint

server = Blueprint(
    'server',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path="/server/static"
)

from . import routes
