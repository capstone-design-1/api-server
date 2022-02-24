import requests
import json
from urllib.parse import quote

from func import getApiKey

class IpQualityScore:
    def __init__(self):
        pass
    
    # API Doc
    # https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview
    def start(self, url: str):
        phishing_site = quote(url, safe="")
        api_key = getApiKey("ipqualityscore")
        url = "https://ipqualityscore.com/api/json/url/{}/{}".format(api_key, phishing_site)
        
        return requests.get(url).json()
        

if __name__ == "__main__":
    print(IpQualityScore().start("https://disocrds.gift/NverABbCacD"))