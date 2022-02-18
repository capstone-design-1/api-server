from flask import Flask
from flask_restx import Resource, Api, Namespace, reqparse

from db.db import *
from feature.func import sqlAlchemyToJson

search = Namespace("Search")

parser = reqparse.RequestParser()
parser.add_argument("limit", type=int, help="전달 받을 목록 개수")


@search.route("/all")
class ApiReport(Resource):
    @search.expect(parser)

    def get(self):
        args = parser.parse_args()
        if args["limit"] == None:
            args["limit"] = 10
        if args["limit"] <= 0:
            return returnError("limit 값은 1 이상 이어야 합니다.", 400)
        
        url_table_result = sqlAlchemyToJson(UrlInfoTable().selectLimit(args["limit"]))
        virustotal_table_result = sqlAlchemyToJson(VirustotalTable().selectLimit(args["limit"]))
        malwares_table_result = sqlAlchemyToJson(MalwaresTable().selectLimit(args["limit"]))
        google_table_result = sqlAlchemyToJson(GoogleTable().selectLimit(args["limit"]))
        phishtank_table_result = sqlAlchemyToJson(PhishtankTable().selectLimit(args["limit"]))

        return_data = []

        for i in range(len(url_table_result))[::-1]:
            return_data.append({
                "url_id" : url_table_result[i]["url_id"],
                "previous_url" : url_table_result[i]["previous_url"],
                "site_image" : url_table_result[i]["site_image"],
                "malicious" : url_table_result[i]["malicious"],
                "init_search_date" : url_table_result[i]["date"],
                "detail" : {
                    "virustotal" : virustotal_table_result[i]["detail"],
                    "malwares" : malwares_table_result[i]["detail"],
                    "google" : google_table_result[i]["detail"],
                    "phishtank" : phishtank_table_result[i]["detail"]
                }
            })

        return return_data

        
def returnError(message: str, status_code: int):
    return {
        "result" : "error",
        "message" : message
    }, status_code