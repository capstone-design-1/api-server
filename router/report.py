from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse
import validators, json, datetime, base64, uuid
from selenium.common.exceptions import TimeoutException, WebDriverException
import multiprocessing

from feature.virustotal import Virustotal
from feature.google_safe_browsing import GoogleSafeBrowsing
from feature.phishtank import Phishtank
from feature.malwares import Malwares
from feature.ipqualityscore import IpQualityScore
from feature.func import *
from feature.chromedriver import Chrome
from db.db import *




api_report = Namespace("API")

parser = reqparse.RequestParser()
parser.add_argument("url", type=str, help="분석할 URL의 base64 encode 값")
parser.add_argument("uuid", type=str, help="디바이스에 할당된 UUID")

MAX_CACHE_MINUTE = 10



@api_report.route("/all")
class ApiReport(Resource):
    @api_report.expect(parser)

    def get(self):

        ###  GET 방식으로 전달받은 데이터 가져오기
        args = parser.parse_args()
        url = args["url"]
        uuid = args["uuid"]


        ###  URL 파라미터 값을 base64 decoding
        try: url = base64.b64decode(url).decode()
        except: return returnError("유효하지 않은 URL 입니다.", 400)


        ###  GET 방식으로 전달받은 데이터 검증
        if not url: return returnError("URL 값이 비어 있습니다.", 400)
        if not uuid: return returnError("uuid 값이 비어 있습니다.", 400)
        if not validateUrlCheck(url): return returnError("URL 형식에 맞지 않습니다.", 400)


        ###  URL 파라미터 값이 분석된 적이 있는지 확인
        result = UrlInfoTable().select(url)


        ###  분석된 이력이 있을 경우
        if result:
            minute = datetime.datetime.now().minute - result[0].date.minute
            image_name = result[0].site_image
            UrlInfoTable().updateCount(result[0])


            ###  마지막 분석 결과가 MAX_CACHE_MINUTE 분이 지났을 경우
            if minute >= MAX_CACHE_MINUTE:


                ###  API 서버로부터 데이터 받아오기
                analyze_result = getInfoFromApiServer(url)

                virustotal_reuslt = analyze_result['virustotal_reuslt']
                google_safe_browsing_result = analyze_result['google_safe_browsing_result']
                phishtank_result = analyze_result['phishtank_result']
                malwares_result = analyze_result['malwares_result']
                ipqualityscore_result = analyze_result['ipqualityscore_result']


                ###  피싱 사이트 여부 판단
                is_malicious = checkMalicious({"virustotal" : virustotal_reuslt,
                                            "google" : google_safe_browsing_result,
                                            "phishtank" : phishtank_result,
                                            "malwares" : malwares_result,
                                            "ipqualityscore" : ipqualityscore_result})


                ###  다시 분석된 정보를 update
                UrlInfoTable().updateData(result[0], is_malicious)
                VirustotalTable().update(json.dumps(virustotal_reuslt), result[0].url_id)
                MalwaresTable().update(json.dumps(malwares_result), result[0].url_id)
                GoogleTable().update(json.dumps(google_safe_browsing_result), result[0].url_id)
                PhishtankTable().update(json.dumps(phishtank_result), result[0].url_id)
                IpQualityScoreTable().update(json.dumps(ipqualityscore_result), result[0].url_id)


            ###  마지막 분석 결과가 MAX_CACHE_MINUTE 분을 지나지 않았을 경우
            else:
                ###  DB에 저장된 데이터를 가져옴
                virustotal_reuslt = json.loads(VirustotalTable().select(result[0].url_id)[0].detail)
                google_safe_browsing_result = json.loads(MalwaresTable().select(result[0].url_id)[0].detail)
                phishtank_result = json.loads(GoogleTable().select(result[0].url_id)[0].detail)
                malwares_result = json.loads(PhishtankTable().select(result[0].url_id)[0].detail)
                ipqualityscore_result = json.loads(IpQualityScoreTable().select(result[0].url_id)[0].detail)
                is_malicious = result[0].malicious


            ###  report를 요청한 uuid가 DB에 존재하지 않을 경우, DB에 추가함
            if uuid not in result[0].uuid:
                update_uuid_value = result[0].uuid + "," + uuid
                UrlInfoTable().updateUUID(result[0], update_uuid_value)
            
            return returnResultData(
                                url = url,
                                site_image = image_name,
                                is_malicious = is_malicious,
                                virustotal = virustotal_reuslt,
                                google_safe_browsing = google_safe_browsing_result,
                                phishtank = phishtank_result,
                                malwares = malwares_result,
                                ipqualityscore = ipqualityscore_result
                            ), 200

        ###  새로운 URL일 경우
        else:
            ###  API 서버로부터 데이터 받아오기
            analyze_result = getInfoFromApiServer(url)

            ###  방문한 사이트 스크린 샷
            image_name = analyze_result["screenshot"]

            ###  피싱 사이트 여부 판단
            is_malicious = checkMalicious({"virustotal" : analyze_result['virustotal_reuslt'],
                                            "google" : analyze_result['google_safe_browsing_result'],
                                            "phishtank" : analyze_result['phishtank_result'],
                                            "malwares" : analyze_result['malwares_result'], 
                                            "ipqualityscore" : analyze_result['ipqualityscore_result']}) 

            ### 조회된 정보를 DB에 insert
            UrlInfoTable().insert(url, is_malicious, image_name, uuid)
            result = UrlInfoTable().select(url)
            VirustotalTable().insert(json.dumps(analyze_result['virustotal_reuslt']), result[0].url_id)
            MalwaresTable().insert(json.dumps(analyze_result['malwares_result']), result[0].url_id)
            GoogleTable().insert(json.dumps(analyze_result['google_safe_browsing_result']), result[0].url_id)
            PhishtankTable().insert(json.dumps(analyze_result['phishtank_result']), result[0].url_id)
            IpQualityScoreTable().insert(json.dumps(analyze_result['ipqualityscore_result']), result[0].url_id)


        return returnResultData(
                                url = url,
                                site_image = image_name,
                                is_malicious = is_malicious,
                                virustotal = analyze_result['virustotal_reuslt'],
                                google_safe_browsing = analyze_result['google_safe_browsing_result'],
                                phishtank = analyze_result['phishtank_result'],
                                malwares = analyze_result['malwares_result'],
                                ipqualityscore = analyze_result['ipqualityscore_result']
                            ), 200



def returnResultData(**kwargs) -> dict:
    """ 분석 결과를 dictionary로 return 하는 함수.

    Args:
        - arg1: 가변 변수의 dictionary로 받게 됨.
    """

    return {
            "url" : kwargs['url'],
            "site_image" : kwargs['site_image'],
            "is_malicious" : kwargs['is_malicious'],
            "detail": {
                "virustotal" : kwargs['virustotal'],
                "google_safe_browsing" : kwargs['google_safe_browsing'],
                "phishtank" : kwargs['phishtank'],
                "malwares" : kwargs['malwares'],
                "ipqualityscore" : kwargs['ipqualityscore']
            }
        }
    

def returnError(message: str, status_code: int):
    """ flask에서 분석 과정 중, 에러가 발생하여 에러 내용을 return 하는 함수.

    Args:
        - arg1: 에러 내용을 작성
        - arg2: 상태코드를 작성
    """

    return {
        "result" : "error",
        "message" : message
    }, status_code


def checkMalicious(data: dict) -> int:
    """ 분석 결과를 통해 피싱 사이트 Y/N 를 판단하는 함수.

    Args:
        - arg1: API 서버로부터 얻은 결과를 dictionary 타입으로 받음

    """

    count = 0

    if data["virustotal"]["malicious"] != 3:
        count += 1
    if data["malwares"]["malicious"] != 0:
        count += 1
    if data["google"]["malicious"] == True:
        count += 1
    if data["phishtank"]["malicious"] == True:
        count += 1
    if data["ipqualityscore"]["malicious"] == True:
        count += 1
    print(count)
    if count > 2:
        return 1
    else:
        return 0


def siteScreenShot(url: str, return_dict: dict, key: str) -> str:
    """ 전달된 URL에 방문하여 페이지를 캡처하는 기능.

    Args:
        - arg1: 방문할 주소
        - arg2: 분석 결과를 받기 위한 변수
        - arg3: 분석 결과를 구분하기 위한 key 

    Note:
        - 해당 함수는 멀티 프로세싱 기반으로 개발됨.
        - return 값을 받기 위해서는 arg2를 통해 전달 받아야 함.

    Raises:
        - TimeoutException: 전달된 URL의 서버로부터 timeout 이 발생할 경우를 예외처리
        - WebDriverException: 예기치 못한 chrome driver 에러를 예외처리
    """

    try:
        driver = Chrome().initDriver()
        driver.get(url)

        image_path = "./static/images/{}.png".format(uuid.uuid1())
        driver.save_screenshot(image_path)

    except TimeoutException as e:
        print("[!] TimeoutException: " + str(e))
        image_path = "./static/images/no_image.png"

    except WebDriverException as e:
        print("[!] WebDriverException: " + str(e))
        image_path = "./static/images/no_image.png"
    
    return_dict[key] = image_path[1:]
    

def getInfoFromApiServer(url: str) -> dict:
    """ API 서버에 분석 요청

    Args:
        - arg1: 방문할 주소
    
    Note:
        - 이 함수는 여러개의 API 서버로부터 요청을 보내기 때문에, 
          시간 절약을 위해 멀티프로세싱 기반으로 여러 함수를 호출.

    """


    manager = multiprocessing.Manager()
    return_dict = manager.dict()
    jobs = list()
    analyze_function_list = {
        "phishtank_result" : Phishtank().start,
        "malwares_result" : Malwares().start,
        "virustotal_reuslt" : Virustotal().start,
        "ipqualityscore_result" : IpQualityScore().start,
        "google_safe_browsing_result" : GoogleSafeBrowsing().start,
    }
    func_list = {
        "screenshot" : siteScreenShot
    }

    for key in func_list.keys():
        p = multiprocessing.Process(target = func_list[key], args=(url, return_dict, key))
        jobs.append(p)
        p.start()

    for key in analyze_function_list.keys():
        p = multiprocessing.Process(target = analyze_function_list[key], args=(url, return_dict, key))
        jobs.append(p)
        p.start()
    
    for proc in jobs:
        proc.join()
    
    return return_dict