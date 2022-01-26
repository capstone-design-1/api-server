from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse
import validators, json, datetime, base64, uuid
from selenium.common.exceptions import TimeoutException, WebDriverException

from feature.virustotal import Virustotal
from feature.google_safe_browsing import GoogleSafeBrowsing
from feature.phishtank import Phishtank
from feature.malwares import Malwares
from feature.func import *
from feature.chromedriver import Chrome
from db.db import *


api_report = Namespace("API")

parser = reqparse.RequestParser()
parser.add_argument("url", type=str, help="분석할 URL의 base64 encode 값")

MAX_CACHE_MINUTE = 10

# TODO
# malicious 판단하는 코드 작성 필요

@api_report.route("/all")
class ApiReport(Resource):
    @api_report.expect(parser)

    def get(self):

        # 전달 받은 URL 가져오기
        args = parser.parse_args()
        url = args["url"]

        # URL -> base64 decoding
        try:
            url = base64.b64decode(url).decode()
        except:
            return return400(2)

        if not url:
            return return400(1)

        if not validateUrlCheck(url):
            return return400(2)

        # 해당 URL이 분석된 적이 있는지 확인
        result = UrlInfoTable().select(url)
        if result:
            minute = datetime.datetime.now().minute - result[0].date.minute
            UrlInfoTable().updateCount(result[0])

            # 10분이 경과 되었을 경우
            if minute >= MAX_CACHE_MINUTE:

                # chrome driver 객체 생성
                chrome_driver = Chrome().initDriver()

                # 해당 URL을 다시 분석
                virustotal_reuslt = Virustotal().start(url)
                google_safe_browsing_result = GoogleSafeBrowsing().start(url)
                phishtank_result = Phishtank().start(url, chrome_driver)
                malwares_result = Malwares().start(url)

                # 피싱 사이트 여부 판단
                is_malicious = checkMalicious({"virustotal" : virustotal_reuslt,
                                            "google" : google_safe_browsing_result,
                                            "phishtank" : phishtank_result,
                                            "malwares" : malwares_result}) 

                # 다시 분석된 정보를 update
                UrlInfoTable().updateData(result[0], is_malicious)
                VirustotalTable().update(json.dumps(virustotal_reuslt), result[0].url_id)
                MalwaresTable().update(json.dumps(malwares_result), result[0].url_id)
                GoogleTable().update(json.dumps(google_safe_browsing_result), result[0].url_id)
                PhishtankTable().update(json.dumps(phishtank_result), result[0].url_id)

                chrome_driver.quit()

            # DB에 저장된 정보를 리턴 (Cache)
            else:
                virustotal_reuslt = json.loads(VirustotalTable().select(result[0].url_id)[0].detail)
                google_safe_browsing_result = json.loads(MalwaresTable().select(result[0].url_id)[0].detail)
                phishtank_result = json.loads(GoogleTable().select(result[0].url_id)[0].detail)
                malwares_result = json.loads(PhishtankTable().select(result[0].url_id)[0].detail)
                is_malicious = result[0].malicious

        # 새로운 URL일 경우
        else:

            # chrome driver 객체 생성
            chrome_driver = Chrome().initDriver()

            # 정보 조회
            virustotal_reuslt = Virustotal().start(url)
            google_safe_browsing_result = GoogleSafeBrowsing().start(url)
            phishtank_result = Phishtank().start(url, chrome_driver)
            malwares_result = Malwares().start(url)

            # 방문한 사이트 스크린 샷
            image_name = siteScreenShot(chrome_driver, url)

            # 피싱 사이트 여부 판단
            is_malicious = checkMalicious({"virustotal" : virustotal_reuslt,
                                            "google" : google_safe_browsing_result,
                                            "phishtank" : phishtank_result,
                                            "malwares" : malwares_result}) 

            # 조회된 정보 insert
            UrlInfoTable().insert(url, is_malicious, "/static/images/{}.png".format(image_name))
            result = UrlInfoTable().select(url)

            VirustotalTable().insert(json.dumps(virustotal_reuslt), result[0].url_id)
            MalwaresTable().insert(json.dumps(malwares_result), result[0].url_id)
            GoogleTable().insert(json.dumps(google_safe_browsing_result), result[0].url_id)
            PhishtankTable().insert(json.dumps(phishtank_result), result[0].url_id)

            chrome_driver.quit()

        return {
            "is_malicious" : is_malicious,
            "detail": {
                "virustotal" : virustotal_reuslt,
                "google_safe_browsing" : google_safe_browsing_result,
                "phishtank" : phishtank_result,
                "malwares" : malwares_result
            }
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

def checkMalicious(data):
    count = 0

    if data["virustotal"]["malicious"] != 0:
        count += 1
    if data["malwares"]["malicious"] != 0:
        count += 1
    if data["google"]["malicious"] == True:
        count += 1
    if data["phishtank"]["malicious"] == True:
        count += 1
    
    if count != 0:
        return True
    else:
        return False

def siteScreenShot(driver, url) -> str:
    try:
        driver.get(url)
        image_name = uuid.uuid1()
        driver.save_screenshot("./static/images/{}.png".format(image_name))
    except TimeoutException:
        image_name = "no_image.png"
    except WebDriverException:
        image_name = "no_image.png"
    
    return image_name