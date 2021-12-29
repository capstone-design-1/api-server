from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse
import validators

from feature.virustotal import Virustotal


api_report = Namespace("API")

parser = reqparse.RequestParser()
parser.add_argument("url", type=str, help="분석할 URL")

@api_report.route("/")
class ApiReport(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()

        try:
            validate_url = validators.url(args["url"])

            if validate_url == True:
                result = Virustotal().start(args["url"])
                return {"result" : result}, 200
            else:
                return {
                    "result" : "error",
                    "message" : "유효하지 않은 URL 입니다."
                }, 400

        except TypeError:
            return {
                "result" : "error",
                "message" : "URL 파라미터가 존재하지 않습니다."
            }, 400