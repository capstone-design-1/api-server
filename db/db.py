from flask_sqlalchemy import SQLAlchemy
import datetime

from db.models import *

# ref : https://lowelllll.github.io/til/2019/04/19/TIL-flask-sqlalchemy-orm/

class UrlInfoTable:
    def __init__(self):
        pass
    
    def insert(self, url: str, count=1):
        url_info = UrlInfo(url = url, count = count, date=datetime.datetime.utcnow())
        db.session.add(url_info)
        db.session.commit()
    
    def select(self, url: str):
        result = UrlInfo.query.filter_by(url=url).all()
        return result
    
    def updateCount(self,data):
        data.count += 1
        db.session.commit()
    
    def updateDate(self, data):
        data.date = datetime.datetime.utcnow()
        db.session.commit()


class VirustotalTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).all()
        return result

    def insert(self, malicious: int, detail: str, url_id: int):
        virustotal_info = VirustotalInfo(malicious=malicious, detail=detail, url_id=url_id)
        db.session.add(virustotal_info)
        db.session.commit()

    def update(self, malicious: int, detail: str, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).first()
        result.malicious = malicious
        result.detail = detail
        db.session.commit()


class MalwaresTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).all()
        return result

    def insert(self, malicious: int, detail: str, url_id: int):
        malwares_info = MalwaresInfo(malicious=malicious, detail=detail, url_id=url_id)
        db.session.add(malwares_info)
        db.session.commit()

    def update(self, malicious: int, detail: str, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).first()
        result.malicious = malicious
        result.detail = detail
        db.session.commit()


class GoogleTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).all()
        return result

    def insert(self, malicious: int, detail: str, url_id: int):
        google_info = GoogleInfo(malicious=malicious, detail=detail, url_id=url_id)
        db.session.add(google_info)
        db.session.commit()
    
    def update(self, malicious: int, detail: str, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).first()
        result.malicious = malicious
        result.detail = detail
        db.session.commit()


class PhishtankTable:
    def __init__(self):
        pass

    def select(self, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).all()
        return result
    
    def insert(self, malicious: int, detail: str, url_id: int):
        phishtank_info = PhishtankInfo(malicious=malicious, detail=detail, url_id=url_id)
        db.session.add(phishtank_info)
        db.session.commit()
    
    def update(self, malicious: int, detail: str, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).first()
        result.malicious = malicious
        result.detail = detail
        db.session.commit()