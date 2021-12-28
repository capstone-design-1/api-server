from flask import Flask
from flask_restx import Resource, Api, Namespace

api_report = Namespace("API")

@api_report.route("/<string:url>")
class ApiMain(Resource):
    def get(self, url):
        return {
            "success" : url
        }