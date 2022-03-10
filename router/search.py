from flask import Flask, Response
from flask_restx import Resource, Api, Namespace, reqparse
import json

from db.db import *
from feature.func import sqlAlchemyToJson

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
        
        if args["malicious"] == None or args["malicious"] == 0:
            url_table_result = sqlAlchemyToJson(UrlInfoTable().selectSearch(args["limit"], args["uuid"], 0))
        else:
            url_table_result = sqlAlchemyToJson(UrlInfoTable().selectSearch(args["limit"], args["uuid"], 1))

        return_data = []

        for i in range(len(url_table_result))[::-1]:
            return_data.append({
                "url_id" : url_table_result[i]["url_id"],
                "previous_url" : url_table_result[i]["previous_url"],
                "site_image" : url_table_result[i]["site_image"],
                "malicious" : url_table_result[i]["malicious"],
                "init_search_date" : url_table_result[i]["date"],
                "detail" : {
                    "virustotal" : sqlAlchemyToJson(VirustotalTable().selectUrlId(args["limit"], url_table_result[i]["url_id"]))[0]["detail"],
                    "malwares" : sqlAlchemyToJson(MalwaresTable().selectUrlId(args["limit"], url_table_result[i]["url_id"]))[0]["detail"],
                    "google" : sqlAlchemyToJson(GoogleTable().selectUrlId(args["limit"], url_table_result[i]["url_id"]))[0]["detail"],
                    "phishtank" : sqlAlchemyToJson(PhishtankTable().selectUrlId(args["limit"], url_table_result[i]["url_id"]))[0]["detail"]
                }
            })

        return Response(json.dumps(return_data), mimetype="application/json")


def returnError(message: str, status_code: int):
    return {
        "result" : "error",
        "message" : message
    }, status_code