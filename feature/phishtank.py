from selenium import webdriver
from bs4 import BeautifulSoup

from feature.chromedriver import Chrome

class Phishtank:
    def __init__(self):
        pass
    
    def start(self, phishing_site: str, return_dict, key: str) -> dict:
        driver = Chrome().initDriver()
        result = {"malicious" : ""}
        
        driver.get("https://phishtank.org")
        
        driver.find_element_by_name("isaphishurl").clear()
        driver.find_element_by_name("isaphishurl").send_keys(phishing_site)
        driver.find_element_by_class_name("submitbutton").click()

        if driver.page_source.find("<b>Is a phish</b>") != -1:
            result["malicious"] = True
        else:
            result["malicious"] = False
        
        driver.quit()

        return_dict[key] = result

if __name__ == "__main__":
    phishing_site = "https://tclbcp.ru/"
    result = Phishtank().start(phishing_site)

    print(result)