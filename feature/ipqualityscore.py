import requests
import json
from urllib.parse import quote

from feature.func import getApiKey

class IpQualityScore:
    def __init__(self):
        pass
    
    # API Doc
    # https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview
    def start(self, url: str) -> dict:
        phishing_site = quote(url, safe="")
        api_key = getApiKey("ipqualityscore")
        url = "https://ipqualityscore.com/api/json/url/{}/{}".format(api_key, phishing_site)

        return_data = {"malicious" : self.isMalicious(requests.get(url).json())}
        
        return return_data
    
    # Standard
    # https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview#:~:text=IPQS%2DKEY%3A%20EzDDnaCfS4xkDO2PqO8LdtUB8mbWKili-,Response%20Field%20Definitions,-Quick%20Notes
    def isMalicious(self, data: dict) -> bool:
        try:
            if data["suspicious"] == True:
                return True
            elif data["risk_score"] >= 75:
                return True
            
            return False

        except KeyError as e:
            print("[!] Not found key. {}".format(e)) 
        
        return False

if __name__ == "__main__":
    print(IpQualityScore().start("https://disocrds.gift/NverABbCacD"))