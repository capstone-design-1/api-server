from flask import Flask
from flask_restx import Namespace, Resource

from db.db import *
from feature.func import sqlAlchemyToJson

db_route = Namespace("DB")

@db_route.route("/sync")
class DbSync(Resource):

    def get(self):
        url_info_table = UrlInfoTable().selectAll()
        virustotal_info_table = VirustotalTable().selectAll()
        malwares_info_table = MalwaresTable().selectAll()
        google_info_table = GoogleTable().selectAll()
        phishtank_info_table = PhishtankTable().selectAll()

        return {
            "count" : len(url_info_table),
            "url_table" : sqlAlchemyToJson(url_info_table),
            "virustotal" : sqlAlchemyToJson(virustotal_info_table),
            "malwares" : sqlAlchemyToJson(malwares_info_table),
            "google" : sqlAlchemyToJson(google_info_table),
            "phishtank" : sqlAlchemyToJson(phishtank_info_table)
        }