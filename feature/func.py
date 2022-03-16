import validators
import json
import datetime

def validateUrlCheck(url: str) -> bool:
    return validators.url(url)


def getApiKey(key: str) -> str:
    f = open("./config/api.json")
    api_key = json.load(f)
    
    return api_key[key]