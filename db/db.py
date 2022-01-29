from flask_sqlalchemy import SQLAlchemy
import datetime

from db.models import *

# ref : https://lowelllll.github.io/til/2019/04/19/TIL-flask-sqlalchemy-orm/

class UrlInfoTable:
    def __init__(self):
        pass
    
    def insert(self, url: str, is_malicious: __init__, image_path, count=1):
        url_info = UrlInfo(previous_url = url, malicious = is_malicious, site_image = image_path, count = count, date=datetime.datetime.utcnow())
        db.session.add(url_info)
        db.session.commit()
    
    def select(self, url: str):
        result = UrlInfo.query.filter_by(previous_url=url).all()
        return result
    
    def updateCount(self, data):
        data.count += 1
        db.session.commit()
    
    def updateData(self, data, is_malicious: int):
        data.date = datetime.datetime.utcnow()
        data.is_malicious = is_malicious
        db.session.commit()
    
    def selectAll(self):
        return UrlInfo.query.all()


class VirustotalTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).all()
        return result

    def insert(self, detail: str, url_id: int):
        virustotal_info = VirustotalInfo(detail=detail, url_id=url_id)
        db.session.add(virustotal_info)
        db.session.commit()

    def update(self, detail: str, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()
    
    def selectAll(self):
        return VirustotalInfo.query.all()


class MalwaresTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).all()
        return result

    def insert(self, detail: str, url_id: int):
        malwares_info = MalwaresInfo(detail=detail, url_id=url_id)
        db.session.add(malwares_info)
        db.session.commit()

    def update(self, detail: str, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()

    def selectAll(self):
        return MalwaresInfo.query.all()

class GoogleTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).all()
        return result

    def insert(self, detail: str, url_id: int):
        google_info = GoogleInfo(detail=detail, url_id=url_id)
        db.session.add(google_info)
        db.session.commit()
    
    def update(self, detail: str, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()
    
    def selectAll(self):
        return GoogleInfo.query.all()


class PhishtankTable:
    def __init__(self):
        pass

    def select(self, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).all()
        return result
    
    def insert(self, detail: str, url_id: int):
        phishtank_info = PhishtankInfo(detail=detail, url_id=url_id)
        db.session.add(phishtank_info)
        db.session.commit()
    
    def update(self, detail: str, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()
    
    def selectAll(self):
        return PhishtankInfo.query.all()