from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class UrlInfo(db.Model):
    __tablename__ = "url_info"

    url_id = db.Column(db.Integer, primary_key = True)
    previous_url = db.Column(db.String)
    destination_url = db.Column(db.String)
    count = db.Column(db.Integer, default=1)
    date = db.Column(db.DateTime)
    malicious = db.Column(db.Boolean, default = False)
    site_image = db.Column(db.String)


class VirustotalInfo(db.Model):
    __tablename__ = "virustotal_info"

    v_id = db.Column(db.Integer, primary_key = True)
    detail = db.Column(db.String)
    url_id = db.Column(db.Integer, db.ForeignKey("url_info.url_id"), nullable=False)


class MalwaresInfo(db.Model):
    __tablename__ = "malwares_info"

    m_id = db.Column(db.Integer, primary_key = True)
    detail = db.Column(db.String)
    url_id = db.Column(db.Integer, db.ForeignKey("url_info.url_id"), nullable=False)


class GoogleInfo(db.Model):
    __tablename__ = "google_info"

    g_id = db.Column(db.Integer, primary_key = True)
    detail = db.Column(db.String)
    url_id = db.Column(db.Integer, db.ForeignKey("url_info.url_id"), nullable=False)


class PhishtankInfo(db.Model):
    __tablename__ = "phishtank_info"

    p_id = db.Column(db.Integer, primary_key = True)
    detail = db.Column(db.String)
    url_id = db.Column(db.Integer, db.ForeignKey("url_info.url_id"), nullable=False)