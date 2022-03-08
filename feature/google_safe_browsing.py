from pysafebrowsing import SafeBrowsing
import json

from feature.func import getApiKey


class GoogleSafeBrowsing:
    def __init__(self):
        pass

    def start(self, url: str, return_dict, key: str) -> dict:
        s = SafeBrowsing(getApiKey("google_api"))
        r = s.lookup_urls([url])
        
        return_dict[key] = r[url]