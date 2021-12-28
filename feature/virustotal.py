import requests
import json
from urllib.parse import urlparse

class Virustotal:
    def __init__(self):
        pass

    def start(self, url: str) -> dict:
        phishing_site = urlparse(url).netloc
        url = "https://www.virustotal.com/api/v3/domains/{}".format(phishing_site)
        headers = {
            "Accept": "application/json",
            "x-apikey": self.getApiKey()
        }

        response = requests.request("GET", url, headers=headers)

        return response.json()
    
    def getApiKey(self) -> str:
        f = open("./config/api.json")
        api_key = json.load(f)
        
        return api_key["virustotal_api"]