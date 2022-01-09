from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse
import validators, json
import datetime
import base64

from feature.virustotal import Virustotal
from feature.google_safe_browsing import GoogleSafeBrowsing
from feature.phishtank import Phishtank
from feature.malwares import Malwares
from feature.func import *
from db.db import *


api_report = Namespace("API")

parser = reqparse.RequestParser()
parser.add_argument("url", type=str, help="분석할 URL")

# TODO
# malicious 판단하는 코드 작성 필요

@api_report.route("/all")
class ApiReport(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()
        url = args["url"]

        try:
            url = base64.b64decode(url).decode()
        except:
            return return400(2)

        if not url:
            return return400(1)

        if not validateUrlCheck(url):
            return return400(2)


        result = UrlInfoTable().select(url)

        if result:
            minute = datetime.datetime.now().minute - result[0].date.minute
            UrlInfoTable().updateCount(result[0])

            if minute >= 1:
                virustotal_reuslt = Virustotal().start(url)
                google_safe_browsing_result = GoogleSafeBrowsing().start(url)
                phishtank_result = Phishtank().start(url)
                malwares_result = Malwares().start(url)

                UrlInfoTable().updateDate(result[0])

                VirustotalTable().update(0, json.dumps(virustotal_reuslt), result[0].url_id)
                MalwaresTable().update(0, json.dumps(malwares_result), result[0].url_id)
                GoogleTable().update(0, json.dumps(google_safe_browsing_result), result[0].url_id)
                PhishtankTable().update(0, json.dumps(phishtank_result), result[0].url_id)

            else:
                virustotal_reuslt = json.loads(VirustotalTable().select(result[0].url_id)[0].detail)
                google_safe_browsing_result = json.loads(MalwaresTable().select(result[0].url_id)[0].detail)
                phishtank_result = json.loads(GoogleTable().select(result[0].url_id)[0].detail)
                malwares_result = json.loads(PhishtankTable().select(result[0].url_id)[0].detail)

        else:
            virustotal_reuslt = Virustotal().start(url)
            google_safe_browsing_result = GoogleSafeBrowsing().start(url)
            phishtank_result = Phishtank().start(url)
            malwares_result = Malwares().start(url)

            UrlInfoTable().insert(url)
            result = UrlInfoTable().select(url)

            VirustotalTable().insert(0, json.dumps(virustotal_reuslt), result[0].url_id)
            MalwaresTable().insert(0, json.dumps(malwares_result), result[0].url_id)
            GoogleTable().insert(0, json.dumps(google_safe_browsing_result), result[0].url_id)
            PhishtankTable().insert(0, json.dumps(phishtank_result), result[0].url_id)

        return {
            "virustotal" : virustotal_reuslt,
            "google_safe_browsing" : google_safe_browsing_result,
            "phishtank" : phishtank_result,
            "malwares" : malwares_result
        }, 200



@api_report.route("/google")
class ApiGoogle(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()
        url = args["url"]

        if not url:
            return return400(1)

        if validateUrlCheck(url):
            google_safe_browsing_result = GoogleSafeBrowsing().start(url)

            return {
                "google_safe_browsing" : google_safe_browsing_result
            }, 200
        
        else:
            return return400(2)


@api_report.route("/malwares")
class ApiMalwares(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()
        url = args["url"]

        if not url:
            return return400(1)

        if validateUrlCheck(url):
            malwares_result = Malwares().start(url)

            return {
                "malwares" : malwares_result
            }, 200
        
        else:
            return return400(2)
    

@api_report.route("/phishtank")
class ApiPhishtank(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()
        url = args["url"]

        if not url:
            return return400(1)

        if validateUrlCheck(url):
            phishtank_result = Phishtank().start(url)

            return {
                "phishtank" : phishtank_result
            }, 200
        
        else:
            return return400(2)


@api_report.route("/virustotal")
class ApiVirustotal(Resource):
    @api_report.expect(parser)

    def get(self):
        args = parser.parse_args()
        url = args["url"]

        if not url:
            return return400(1)

        if validateUrlCheck(url):
            virustotal_reuslt = Virustotal().start(url)

            return {
                "virustotal" : virustotal_reuslt
            }, 200
        
        else:
            return return400(2)


def return400(*args):
    if args[0] == 1:
        return {
            "result" : "error",
            "message" : "URL 값이 비어 있습니다."
        }, 400

    elif args[0] == 2:
        return {
            "result" : "error",
            "message" : "유효하지 않은 URL 입니다."
        }, 400