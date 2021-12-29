from selenium import webdriver
from bs4 import BeautifulSoup

class Phishtank:
    def __init__(self):
        pass
    
    def start(self, phishing_site: str) -> dict:
        result = {"malicious" : ""}
        
        driver = self.initDriver()
        driver.get("https://phishtank.org")
        
        driver.find_element_by_name("isaphishurl").clear()
        driver.find_element_by_name("isaphishurl").send_keys(phishing_site)
        driver.find_element_by_class_name("submitbutton").click()

        if driver.page_source.find("<b>Is a phish</b>") != -1:
            result["malicious"] = True
        else:
            result["malicious"] = False
        
        return result

    def initDriver(self):
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument('headless')
        chrome_options.add_argument('window-size=1920x1080')
        chrome_options.add_argument("disable-gpu")
        chrome_options.add_argument("lang=ko_KR")
        chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.84 Safari/537.36')
        chrome_options.add_experimental_option("prefs", {
            "download_restrictions": 3
        })

        driver = webdriver.Chrome(executable_path="/home/ubuntu/git/api-server/feature/chromedriver", chrome_options=chrome_options)

        return driver

if __name__ == "__main__":
    phishing_site = "https://tclbcp.ru/"
    result = Phishtank().start(phishing_site)

    print(result)