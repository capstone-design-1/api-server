import requests
import json
from urllib.parse import urlparse

from feature.func import getApiKey


class Virustotal:
    def __init__(self):
        pass

    def start(self, url: str) -> dict:
        phishing_site = urlparse(url).netloc
        url = "https://www.virustotal.com/api/v3/domains/{}".format(phishing_site)
        headers = {
            "Accept": "application/json",
            "x-apikey": getApiKey("virustotal_api")
        }

        response = requests.request("GET", url, headers=headers)

        return response.json()["data"]["attributes"]["last_analysis_stats"]