from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse
import validators

from feature.virustotal import Virustotal
from feature.google_safe_browsing import GoogleSafeBrowsing
from feature.phishtank import Phishtank
from feature.malwares import Malwares
from feature.func import *


api_report = Namespace("API")

parser = reqparse.RequestParser()
parser.add_argument("url", type=str, help="분석할 URL")

@api_report.route("/all")
class ApiReport(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()

        try:
            if validateUrlCheck(args["url"]):
                virustotal_reuslt = Virustotal().start(args["url"])
                google_safe_browsing_result = GoogleSafeBrowsing().start(args["url"])
                phishtank_result = Phishtank().start(args["url"])
                malwares_result = Malwares().start(args["url"])

                return {
                    "virustotal" : virustotal_reuslt,
                    "google_safe_browsing" : google_safe_browsing_result,
                    "phishtank" : phishtank_result,
                    "malwares" : malwares_result
                }, 200

            else:
                return return400(2)

        except TypeError:
            return return400(1)



@api_report.route("/google")
class ApiGoogle(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()

        try:
            if validateUrlCheck(args["url"]):
                google_safe_browsing_result = GoogleSafeBrowsing().start(args["url"])

                return {
                    "google_safe_browsing" : google_safe_browsing_result
                }, 200
            
            else:
                return return400(2)

        except TypeError:
            return return400(1)


@api_report.route("/malwares")
class ApiMalwares(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()

        try:
            if validateUrlCheck(args["url"]):
                malwares_result = Malwares().start(args["url"])

                return {
                    "malwares" : malwares_result
                }, 200
            
            else:
                return return400(2)

        except TypeError:
            return return400(1)
    

@api_report.route("/phishtank")
class ApiPhishtank(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()

        try:
            if validateUrlCheck(args["url"]):
                phishtank_result = Phishtank().start(args["url"])

                return {
                    "phishtank" : phishtank_result
                }, 200
            
            else:
                return return400(2)

        except TypeError:
            return return400(1)


@api_report.route("/virustotal")
class ApiVirustotal(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()

        try:
            if validateUrlCheck(args["url"]):
                virustotal_reuslt = Virustotal().start(args["url"])

                return {
                    "virustotal" : virustotal_reuslt
                }, 200
            
            else:
                return return400(2)

        except TypeError:
            return return400(1)


def return400(mode):
    if mode == 1:
        return {
            "result" : "error",
            "message" : "URL 파라미터가 존재하지 않습니다."
        }, 400

    elif mode == 2:
        return {
            "result" : "error",
            "message" : "유효하지 않은 URL 입니다."
        }, 400