from flask import Flask
from flask_restx import Resource, Api
import sys
from werkzeug.serving import WSGIRequestHandler

from router.report import api_report
from router.db import db_route
from router.search import search

from db.db import *
from feature.func import getApiKey

app = Flask(__name__)
api = Api(app)
WSGIRequestHandler.protocol_version = "HTTP/1.1"

api.add_namespace(api_report, "/api/report")
api.add_namespace(search, "/search")
api.add_namespace(db_route, "/db")

##### db init ####
def initDB():
    createDatabase()
#### db init end ###


@app.errorhandler(Exception)
def server_error(error):
    print(error)
    return "test", 500

@app.route("/logging")
def logging():
    data = open("nohup.out", "r").readlines()
    return "<br>".join(data)

if __name__ == '__main__':
    initDB()
    if len(sys.argv) == 2 and sys.argv[1] == "debug":
        app.run(debug=True, host="0.0.0.0", port=8080)

    else:
        app.run(debug=False, host="0.0.0.0", port=8080)