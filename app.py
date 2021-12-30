from flask import Flask
from flask_restx import Resource, Api
import os

from router.report import api_report
from db.models import db
from feature.func import getApiKey

app = Flask(__name__)
api = Api(app)

api.add_namespace(api_report, "/api/report")

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

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)