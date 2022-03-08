from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager

class Chrome:
    def __init__(self):
        self.driver = None
    
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

        self.driver = webdriver.Chrome(ChromeDriverManager().install(), chrome_options=chrome_options)
        self.driver.set_page_load_timeout(10)

        return self.driver
    
    def getCurrentDomain():
        return self.driver.current_url