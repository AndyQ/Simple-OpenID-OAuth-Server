from flask import Blueprint

resource = Blueprint(
    'resource',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path="/static"
)

from . import routes
