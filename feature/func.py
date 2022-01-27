import validators
import json
import datetime

def validateUrlCheck(url: str) -> bool:
    return validators.url(url)


def getApiKey(key: str) -> str:
    f = open("./config/api.json")
    api_key = json.load(f)
    
    return api_key[key]


def sqlAlchemyToJson(sql_row_data: list) -> list:
    result = list()
    index = 0

    for data in sql_row_data:
        result.append(dict())
        for key in data.__dict__.keys():
            if key == "_sa_instance_state":
                continue
            
            if type(data.__dict__[key]) == datetime.datetime:
                result[index][key] = str(data.__dict__[key])
            elif key == "detail":
                result[index][key] = json.loads(data.__dict__[key])
            else:
                result[index][key] = data.__dict__[key]
        
        index += 1
    
    return result