from flask import Flask
from flask_restx import Resource, Api
import os
from werkzeug.serving import WSGIRequestHandler

from router.report import api_report
from router.db import db_route
from router.search import search

from db.models import db
from feature.func import getApiKey

app = Flask(__name__)
api = Api(app)
WSGIRequestHandler.protocol_version = "HTTP/1.1"

api.add_namespace(api_report, "/api/report")
api.add_namespace(search, "/search")
api.add_namespace(db_route, "/db")

##### db init ####
basedir = os.path.abspath(os.path.dirname(__file__))
dbfile = os.path.join(basedir, 'db.sqlite')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + dbfile
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = getApiKey("db_secret_key")

db.init_app(app)
db.app = app
db.create_all()
#### db init end ###

print(1)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)