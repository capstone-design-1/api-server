from flask import Flask, Response
from flask_restx import Resource, Api, Namespace, reqparse
import json

from db.table import *

search = Namespace("Search")

parser = reqparse.RequestParser()
parser.add_argument("limit", type=int, help="전달 받을 목록 개수")
parser.add_argument("uuid", type=str, help="디바이스에 할당된 UUID")
parser.add_argument("malicious", type=int, help="악성 URL 결과만 받을지 여부")


@search.route("/all")
class ApiReport(Resource):
    @search.expect(parser)

    def get(self):
        args = parser.parse_args()
        if args["limit"] == None:
            args["limit"] = 10
        if args["limit"] <= 0:
            return returnError("limit 값은 1 이상 이어야 합니다.", 400)
        if not args["uuid"]:
            return returnError("uuid 값이 비어 있습니다.", 400)
        
        # TODO selectSearch 함수 수정해야 됨
        if args["malicious"] == None or args["malicious"] == 0:
            url_table_result = UrlInfo().getUserData(args["uuid"], 0, args["limit"])
        else:
            url_table_result = UrlInfo().getUserData(args["uuid"], 1, args["limit"])

        return_data = []

        for i in range(len(url_table_result)):
            return_data.append({
                "url_id" : url_table_result[i]["url_idx"],
                "search_url" : url_table_result[i]["search_url"],
                "site_image" : url_table_result[i]["site_image"],
                "malicious" : url_table_result[i]["malicious"],
                "search_time" : url_table_result[i]["search_time"],
                "detail" : {
                    "virustotal" : json.loads(VirustotalInfo().getData(url_table_result[i]["url_idx"])[0][1]),
                    "malwares" : json.loads(MalwaresInfo().getData(url_table_result[i]["url_idx"])[0][1]),
                    "google" : json.loads(GoogleInfo().getData(url_table_result[i]["url_idx"])[0][1]),
                    "phishtank" : json.loads(PhishtankInfo().getData(url_table_result[i]["url_idx"])[0][1]),
                    "ipqualityscore" : json.loads(IpQalityScoreInfo().getData(url_table_result[i]["url_idx"])[0][1])
                }
            })

        return Response(json.dumps(return_data), mimetype="application/json")


def returnError(message: str, status_code: int):
    return {
        "result" : "error",
        "message" : message
    }, status_code