import validators
import json
import datetime

def validateUrlCheck(url: str) -> bool:
    return validators.url(url)


def getApiKey(key: str) -> str:
    f = open("./config/api.json")
    api_key = json.load(f)
    
    return api_key[key]


def sqlAlchemyToJson(sql_row_data: list) -> dict:
    result = dict()

    for data in sql_row_data:
        for key in data.__dict__.keys():
            if key == "_sa_instance_state":
                continue
            
            if type(data.__dict__[key]) == datetime.datetime:
                result[key] = str(data.__dict__[key])
            else:
                result[key] = data.__dict__[key]
    
    return json.dumps(result)