from flask import Flask
from flask_restx import Namespace, Resource

from db.table import *

db_route = Namespace("DB")

@db_route.route("/sync")
class DbSync(Resource):

    def get(self):
        url_info_table = UrlInfo().getAllData()
        virustotal_info_table = VirustotalInfo().getAllData()
        malwares_info_table = MalwaresInfo().getAllData()
        google_info_table = GoogleInfo().getAllData()
        phishtank_info_table = PhishtankInfo().getAllData()
        user_info_table = UserInfo().getAllData()

        return {
            "count" : len(url_info_table),
            "url_table" : url_info_table,
            "virustotal" : virustotal_info_table,
            "malwares" : malwares_info_table,
            "google" : google_info_table,
            "phishtank" : phishtank_info_table,
            "user" : user_info_table
        }