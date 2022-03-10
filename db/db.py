from flask_sqlalchemy import SQLAlchemy
import datetime

from db.models import *

# ref : https://lowelllll.github.io/til/2019/04/19/TIL-flask-sqlalchemy-orm/

class UrlInfoTable:
    def __init__(self):
        pass
    
    def insert(self, url: str, is_malicious: __init__, image_path, uuid, count=1):
        url_info = UrlInfo(previous_url = url, malicious = is_malicious, site_image = image_path, count = count, date=datetime.datetime.utcnow(), uuid=uuid)
        db.session.add(url_info)
        db.session.commit()
    
    def select(self, url: str):
        result = UrlInfo.query.filter_by(previous_url=url).all()
        return result
    
    def selectSearch(self, limit: int, uuid: str, malicious: int):
        if malicious:
            result = UrlInfo.query.filter(UrlInfo.uuid.like("%{}%".format(uuid))) \
                                    .filter(UrlInfo.malicious.like(malicious)) \
                                    .limit(limit).all()
        else:
            result = UrlInfo.query.filter(UrlInfo.uuid.like("%{}%".format(uuid))) \
                                    .limit(limit).all()

        return result
    
    def selectAll(self):
        return UrlInfo.query.all()
    
    def updateCount(self, data):
        data.count += 1
        db.session.commit()
    
    def updateData(self, data, is_malicious: int):
        data.date = datetime.datetime.utcnow()
        data.is_malicious = is_malicious
        db.session.commit()
    
    def updateUUID(self, data, uuid: str):
        data.uuid = uuid
        db.session.commit()


class VirustotalTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).all()
        return result
    
    def selectUrlId(self, limit: int, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).limit(limit).all()
        return result
    
    def selectAll(self):
        return VirustotalInfo.query.all()

    def insert(self, detail: str, url_id: int):
        virustotal_info = VirustotalInfo(detail=detail, url_id=url_id)
        db.session.add(virustotal_info)
        db.session.commit()

    def update(self, detail: str, url_id: int):
        result = VirustotalInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()


class MalwaresTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).all()
        return result

    def selectUrlId(self, limit: int, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).limit(limit).all()
        return result
    
    def selectAll(self):
        return MalwaresInfo.query.all()

    def insert(self, detail: str, url_id: int):
        malwares_info = MalwaresInfo(detail=detail, url_id=url_id)
        db.session.add(malwares_info)
        db.session.commit()

    def update(self, detail: str, url_id: int):
        result = MalwaresInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()


class GoogleTable:
    def __init__(self):
        pass
    
    def select(self, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).all()
        return result

    def selectUrlId(self, limit: int, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).limit(limit).all()
        return result
    
    def selectAll(self):
        return GoogleInfo.query.all()

    def insert(self, detail: str, url_id: int):
        google_info = GoogleInfo(detail=detail, url_id=url_id)
        db.session.add(google_info)
        db.session.commit()
    
    def update(self, detail: str, url_id: int):
        result = GoogleInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()


class PhishtankTable:
    def __init__(self):
        pass

    def select(self, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).all()
        return result
    
    def selectUrlId(self, limit: int, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).limit(limit).all()
        return result
    
    def selectAll(self):
        return PhishtankInfo.query.all()
    
    def insert(self, detail: str, url_id: int):
        phishtank_info = PhishtankInfo(detail=detail, url_id=url_id)
        db.session.add(phishtank_info)
        db.session.commit()
    
    def update(self, detail: str, url_id: int):
        result = PhishtankInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()


class IpQualityScoreTable:
    def __init__(self):
        pass

    def select(self, url_id: int):
        result = IpQualityScoreInfo.query.filter_by(url_id=url_id).all()
        return result
    
    def selectUrlId(self, limit: int, url_id: int):
        result = IpQualityScoreInfo.query.filter_by(url_id=url_id).limit(limit).all()
        return result
    
    def selectAll(self):
        return IpQualityScoreInfo.query.all()
    
    def insert(self, detail: str, url_id: int):
        phishtank_info = IpQualityScoreInfo(detail=detail, url_id=url_id)
        db.session.add(phishtank_info)
        db.session.commit()
    
    def update(self, detail: str, url_id: int):
        result = IpQualityScoreInfo.query.filter_by(url_id=url_id).first()
        result.detail = detail
        db.session.commit()