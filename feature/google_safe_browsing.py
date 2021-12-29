from pysafebrowsing import SafeBrowsing
import json


class GoogleSafeBrowsing:
    def __init__(self):
        pass

    def start(self, url: str) -> dict:
        s = SafeBrowsing(self.getApiKey())
        r = s.lookup_urls([url])
        
        return r[url]
    
    def getApiKey(self) -> str:
        f = open("./config/api.json")
        api_key = json.load(f)
        
        return api_key["google_api"]