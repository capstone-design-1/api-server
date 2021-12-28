from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse

from feature.virustotal import Virustotal


api_report = Namespace("API")

parser = reqparse.RequestParser()
parser.add_argument("url", type=str, help="분석할 URL")

@api_report.route("/")
class ApiReport(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()
        result = Virustotal().start(args["url"])

        return {"result" : result}