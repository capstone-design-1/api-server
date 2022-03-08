from selenium import webdriver
from bs4 import BeautifulSoup

from feature.chromedriver import Chrome

class Phishtank:
    def __init__(self):
        self.driver = Chrome().initDriver()
        pass
    
    def start(self, phishing_site: str) -> dict:
        result = {"malicious" : ""}
        
        self.driver.get("https://phishtank.org")
        
        self.driver.find_element_by_name("isaphishurl").clear()
        self.driver.find_element_by_name("isaphishurl").send_keys(phishing_site)
        self.driver.find_element_by_class_name("submitbutton").click()

        if self.driver.page_source.find("<b>Is a phish</b>") != -1:
            result["malicious"] = True
        else:
            result["malicious"] = False
        
        self.driver.quit()

        return result

if __name__ == "__main__":
    phishing_site = "https://tclbcp.ru/"
    result = Phishtank().start(phishing_site)

    print(result)