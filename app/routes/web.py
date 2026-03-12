import os
from flask import Blueprint, Response

web = Blueprint('web', __name__)


@web.route('/')
def index():
    template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'templates', 'index.html')
    with open(template_path, 'r', encoding='utf-8') as f:
        return Response(f.read(), mimetype='text/html')


@web.route('/login')
def login():
    template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'templates', 'login.html')
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/html')
    return Response('<h1>Login not implemented</h1>', mimetype='text/html')
