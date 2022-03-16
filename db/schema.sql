CREATE TABLE url_info (
    url_idx         INTEGER PRIMARY KEY AUTOINCREMENT,
    search_url      TEXT NOT NULL,
    malicious       INTEGER NOT NULL DEFAULT 1,
    site_image      TEXT NOT NULL    
);

CREATE TABLE user_info (
    user_idx        INTEGER PRIMARY KEY,
    uuid            TEXT NOT NULL,
    search_time     TEXT NOT NULL,
    url_idx         INTEGER,
    foreign key (url_idx) references url_info(url_idx) 
);

CREATE TABLE virustotal_info (
    v_idx   INTEGER  PRIMARY KEY,
    detail  TEXT NOT NULL,
    url_idx INTEGER,
    foreign key (url_idx) references url_info(url_idx) 
);

CREATE TABLE malwares_info (
    m_idx   INTEGER PRIMARY KEY,
    detail  TEXT NOT NULL,
    url_idx INTEGER,
    foreign key (url_idx) references url_info(url_idx) 
);

CREATE TABLE google_info (
    g_idx   INTEGER PRIMARY KEY,
    detail  TEXT NOT NULL,
    url_idx INTEGER,
    foreign key (url_idx) references url_info(url_idx) 
);

CREATE TABLE phishtank_info (
    p_idx   INTEGER PRIMARY KEY,
    detail  TEXT NOT NULL,
    url_idx INTEGER,
    foreign key (url_idx) references url_info(url_idx) 
);

CREATE TABLE ipqualityscore_info (
    i_idx   INTEGER PRIMARY KEY,
    detail  TEXT NOT NULL,
    url_idx INTEGER,
    foreign key (url_idx) references url_info(url_idx) 
);


