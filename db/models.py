from flask_sqlalchemy import flask_sqlalchemy

db = SQLAlchemy()

class UrlInfo(db.Model):
    __tablename__ = "url_info"

    url_id = db.Column(db.Integer, primary_key = True)
    url = db.Column(db.String)
    count = db.Coulumn(db.Integer)