from flask import Flask
from flask_restx import Resource, Api
from router.report import api_report

app = Flask(__name__)
api = Api(app)

api.add_namespace(api_report, "/api/report")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)