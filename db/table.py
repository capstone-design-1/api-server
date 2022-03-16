import sqlite3 as sql

from db.db import dbConnection

class UrlInfo:
    
    def __init__(self):
        self.__tablename__ = "url_info"
    
    def insertData(self, url, malicious, site_image):
        query = """
            INSERT INTO {0} (search_url, malicious, site_image)
            VALUES (?, ?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (url, malicious, site_image, ))
        con.commit()
        con.close()

    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)
        
        return cur.fetchall()

    def getUrlData(self, url: str):
        query = """
            SELECT * FROM {0}
            WHERE
            search_url = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (url,))

        return cur.fetchall()
    
    def getUserData(self, uuid: str, malicious: str, limit: int):
        con = dbConnection()
        cur = con.cursor()
        return_data = list()
        result = list()

        if malicious:
            query = """
                SELECT url.url_idx, url.search_url, url.malicious, url.site_image, user.search_time
                FROM url_info as url
                JOIN user_info as user
                ON url.url_idx = user.url_idx
                WHERE
                url.malicious = ? AND user.uuid = ?
                ORDER BY user.search_time DESC
                LIMIT ?
            """
            cur.execute(query, (malicious, uuid, limit,))

            result = cur.fetchall()

        else:
            query = """
                SELECT url.url_idx, url.search_url, url.malicious, url.site_image, user.search_time
                FROM url_info as url
                JOIN user_info as user
                ON url.url_idx = user.url_idx
                WHERE
                user.uuid = ?
                ORDER BY user.search_time DESC
                LIMIT ?
            """
            cur.execute(query, (uuid, limit,))

            result = cur.fetchall()
        
        for i in range(len(result)):
            return_data.append({
                "url_idx" : result[i][0],
                "search_url" : result[i][1],
                "malicious" : result[i][2],
                "site_image" : result[i][3],
                "search_time" : result[i][4]
            })

        return return_data

class UserInfo:

    def __init__(self):
        self.__tablename__ = "user_info"

    def insertData(self, uuid, search_time, url_idx):
        query = """
            INSERT INTO {0} (uuid, search_time, url_idx)
            VALUES (?, ?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (uuid, str(search_time), url_idx, ))
        con.commit()
        con.close()

    def updateData(self, url_idx: int, search_time, uuid: str):
        query = """
            UPDATE {0}
            SET search_time = ?
            WHERE url_idx = ? AND uuid = ?
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (str(search_time), url_idx, uuid,))
        con.commit()
        con.close()

    def getData(self, uuid: str):
        query = """
            SELECT * FROM {0}
            WHERE
            uuid = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (uuid, ))

        return cur.fetchall()
    
    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)

        return cur.fetchall()
    
    def findUserData(self, url_info_data: list, uuid: str):
        url_idx_list = []
        for data in url_info_data:
            url_idx_list.append(str(data[0]))
            
        query = """
            SELECT count(uuid) FROM {0}
            WHERE
                url_idx IN ({1})
                AND
                uuid = ?
        """.format(self.__tablename__, ",".join(url_idx_list))

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (uuid, ))

        return cur.fetchall()


class VirustotalInfo:
    
    def __init__(self):
        self.__tablename__ = "virustotal_info"
    
    def insertData(self, detail: str, url_idx: int):
        query = """
            INSERT INTO {0} (detail, url_idx)
            VALUES (?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx, ))
        con.commit()
        con.close()
    
    def getData(self, url_idx: int):
        query = """
            SELECT * FROM {0}
            WHERE
            url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (url_idx, ))

        return cur.fetchall()
    
    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)

        return cur.fetchall()
    
    def updateData(self, detail: str, url_idx: int):
        query = """
            UPDATE {0}
            SET detail = ?
            WHERE url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx,))
        con.commit()
        con.close()


class MalwaresInfo:
    
    def __init__(self):
        self.__tablename__ = "malwares_info"
    
    def insertData(self, detail: str, url_idx: int):
        query = """
            INSERT INTO {0} (detail, url_idx)
            VALUES (?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx, ))
        con.commit()
        con.close()
    
    def getData(self, url_idx: int):
        query = """
            SELECT * FROM {0}
            WHERE
            url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (url_idx, ))

        return cur.fetchall()
    
    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)

        return cur.fetchall()
    
    def updateData(self, detail: str, url_idx: int):
        query = """
            UPDATE {0}
            SET detail = ?
            WHERE url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx,))
        con.commit()
        con.close()


class GoogleInfo:
    
    def __init__(self):
        self.__tablename__ = "google_info"
    
    def insertData(self, detail: str, url_idx: int):
        query = """
            INSERT INTO {0} (detail, url_idx)
            VALUES (?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx, ))
        con.commit()
        con.close()
    
    def getData(self, url_idx: int):
        query = """
            SELECT * FROM {0}
            WHERE
            url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (url_idx, ))

        return cur.fetchall()
    
    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)

        return cur.fetchall()
    
    def updateData(self, detail: str, url_idx: int):
        query = """
            UPDATE {0}
            SET detail = ?
            WHERE url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx,))
        con.commit()
        con.close()


class PhishtankInfo:
    
    def __init__(self):
        self.__tablename__ = "phishtank_info"
    
    def insertData(self, detail: str, url_idx: int):
        query = """
            INSERT INTO {0} (detail, url_idx)
            VALUES (?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx, ))
        con.commit()
        con.close()
    
    def getData(self, url_idx: int):
        query = """
            SELECT * FROM {0}
            WHERE
            url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (url_idx, ))

        return cur.fetchall()
    
    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)

        return cur.fetchall()
    
    def updateData(self, detail: str, url_idx: int):
        query = """
            UPDATE {0}
            SET detail = ?
            WHERE url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx,))
        con.commit()
        con.close()


class IpQalityScoreInfo:
    
    def __init__(self):
        self.__tablename__ = "ipqualityscore_info"
    
    def insertData(self, detail: str, url_idx: int):
        query = """
            INSERT INTO {0} (detail, url_idx)
            VALUES (?, ?)
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx, ))
        con.commit()
        con.close()
    
    def getData(self, url_idx: int):
        query = """
            SELECT * FROM {0}
            WHERE
            url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query, (url_idx, ))

        return cur.fetchall()
    
    def getAllData(self):
        query = """
            SELECT * FROM {0}
        """.format(self.__tablename__)

        con = dbConnection()
        cur = con.cursor()
        cur.execute(query)

        return cur.fetchall()
    
    def updateData(self, detail: str, url_idx: int):
        query = """
            UPDATE {0}
            SET detail = ?
            WHERE url_idx = ?
        """.format(self.__tablename__)

        con = dbConnection()
        con.cursor().execute(query, (detail, url_idx,))
        con.commit()
        con.close()

