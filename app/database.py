import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel_cve.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cpes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        cpe23uri TEXT UNIQUE,
        part TEXT,
        vendor TEXT,
        product TEXT,
        version TEXT
    );
    """)
    
    # SQLite FTS5 Virtual Table for high-speed prefix/fuzzy matches
    cursor.execute("""
    CREATE VIRTUAL TABLE IF NOT EXISTS cpes_fts USING fts5(
        vendor,
        product,
        cpe23uri UNINDEXED,
        content='cpes',
        content_rowid='id'
    );
    """)
    
    # Create Triggers to sync FTS5 virtual table with cpes
    cursor.execute("""
    CREATE TRIGGER IF NOT EXISTS cpes_ai AFTER INSERT ON cpes BEGIN
        INSERT INTO cpes_fts(rowid, vendor, product, cpe23uri)
        VALUES (new.id, new.vendor, new.product, new.cpe23uri);
    END;
    """)
    
    cursor.execute("""
    CREATE TRIGGER IF NOT EXISTS cpes_ad AFTER DELETE ON cpes BEGIN
        INSERT INTO cpes_fts(cpes_fts, rowid, vendor, product, cpe23uri)
        VALUES('delete', old.id, old.vendor, old.product, old.cpe23uri);
    END;
    """)
    
    cursor.execute("""
    CREATE TRIGGER IF NOT EXISTS cpes_au AFTER UPDATE ON cpes BEGIN
        INSERT INTO cpes_fts(cpes_fts, rowid, vendor, product, cpe23uri)
        VALUES('delete', old.id, old.vendor, old.product, old.cpe23uri);
        INSERT INTO cpes_fts(rowid, vendor, product, cpe23uri)
        VALUES (new.id, new.vendor, new.product, new.cpe23uri);
    END;
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE,
        description TEXT,
        cvss_v3_score REAL,
        cvss_v2_score REAL,
        severity TEXT,
        published_date TEXT,
        cpe23uri TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        software_json TEXT
    );
    """)

    conn.commit()
    seed_sample_data(conn)
    conn.close()

def seed_sample_data(conn):
    cursor = conn.cursor()
    
    # Check if database has data already
    cursor.execute("SELECT COUNT(*) FROM cpes")
    if cursor.fetchone()[0] > 0:
        return
        
    print("Pre-seeding sample database with common vulnerable softwares...")
    
    # Format: (title, cpe23uri, part, vendor, product, version)
    sample_cpes = [
        ("Google Chrome 100.0.4896.60", "cpe:2.3:a:google:chrome:100.0.4896.60:*:*:*:*:*:*:*", "a", "google", "chrome", "100.0.4896.60"),
        ("Google Chrome 101.0.4951.41", "cpe:2.3:a:google:chrome:101.0.4951.41:*:*:*:*:*:*:*", "a", "google", "chrome", "101.0.4951.41"),
        ("VideoLAN VLC Media Player 3.0.16", "cpe:2.3:a:videolan:vlc_media_player:3.0.16:*:*:*:*:*:*:*", "a", "videolan", "vlc_media_player", "3.0.16"),
        ("WinRAR 6.11", "cpe:2.3:a:winrar:winrar:6.11:*:*:*:*:*:*:*", "a", "winrar", "winrar", "6.11"),
        ("Zoom Client 5.12.0", "cpe:2.3:a:zoom:zoom:5.12.0:*:*:*:*:*:*:*", "a", "zoom", "zoom", "5.12.0"),
        ("Git for Windows 2.39.0", "cpe:2.3:a:git-scm:git:2.39.0:*:*:*:*:*:*:*", "a", "git-scm", "git", "2.39.0"),
        ("Mozilla Firefox 98.0", "cpe:2.3:a:mozilla:firefox:98.0:*:*:*:*:*:*:*", "a", "mozilla", "firefox", "98.0"),
        ("Microsoft Office 2019", "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*", "a", "microsoft", "office", "2019"),
        ("Adobe Reader DC 2021.007.20091", "cpe:2.3:a:adobe:acrobat_reader_dc:20.007.20091:*:*:*:*:*:*:*", "a", "adobe", "acrobat_reader_dc", "20.007.20091"),
        ("7-Zip 21.07", "cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*", "a", "7-zip", "7-zip", "21.07")
    ]
    
    for cpe in sample_cpes:
        try:
            cursor.execute("""
            INSERT OR IGNORE INTO cpes (title, cpe23uri, part, vendor, product, version)
            VALUES (?, ?, ?, ?, ?, ?)
            """, cpe)
            # Sync FTS
            cursor.execute("SELECT last_insert_rowid()")
            rowid = cursor.fetchone()[0]
            cursor.execute("""
            INSERT OR IGNORE INTO cpes_fts (rowid, vendor, product, cpe23uri)
            VALUES (?, ?, ?, ?)
            """, (rowid, cpe[3], cpe[4], cpe[1]))
        except Exception as e:
            print(f"Error seeding CPE {cpe[1]}: {e}")

    # Format: (cve_id, description, cvss_v3_score, cvss_v2_score, severity, published_date, cpe23uri)
    sample_cves = [
        ("CVE-2022-1134", "Type Confusion in V8 in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit directory corruption via a crafted HTML page.", 8.8, 6.8, "HIGH", "2022-04-26", "cpe:2.3:a:google:chrome:100.0.4896.60:*:*:*:*:*:*:*"),
        ("CVE-2022-38171", "An integer overflow vulnerability in VLC Media Player 3.0.16 and prior allows a remote attacker to trigger an out-of-bounds write or read via a maliciously crafted media file.", 7.8, 5.0, "HIGH", "2022-08-22", "cpe:2.3:a:videolan:vlc_media_player:3.0.16:*:*:*:*:*:*:*"),
        ("CVE-2023-38831", "WinRAR before 6.23 allows remote attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive.", 7.8, 4.3, "HIGH", "2023-08-24", "cpe:2.3:a:winrar:winrar:6.11:*:*:*:*:*:*:*"),
        ("CVE-2022-36930", "Zoom Client for Meetings for Windows prior to version 5.12.0 contains a Remote Code Execution vulnerability due to insecure DLL loading.", 8.8, 7.5, "HIGH", "2022-09-13", "cpe:2.3:a:zoom:zoom:5.12.0:*:*:*:*:*:*:*"),
        ("CVE-2023-22490", "Git before 2.39.2 allows local clone optimization bypasses that can lead to remote code execution under specific circumstances.", 9.8, 8.5, "CRITICAL", "2023-02-14", "cpe:2.3:a:git-scm:git:2.39.0:*:*:*:*:*:*:*"),
        ("CVE-2022-1096", "Type Confusion in V8 in Google Chrome prior to 99.0.4844.84 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.", 8.8, 6.8, "HIGH", "2022-03-29", "cpe:2.3:a:google:chrome:100.0.4896.60:*:*:*:*:*:*:*"),
        ("CVE-2022-26485", "Use-after-free vulnerability in the XSLT processor of Mozilla Firefox before 98.0 allowed remote code execution.", 9.8, 9.3, "CRITICAL", "2022-03-05", "cpe:2.3:a:mozilla:firefox:98.0:*:*:*:*:*:*:*"),
        ("CVE-2022-30190", "Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability (Follina) affecting Microsoft Office 2019 and older versions.", 7.8, 9.3, "HIGH", "2022-05-31", "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"),
        ("CVE-2021-40731", "Adobe Acrobat Reader DC version 21.007.20091 and earlier is affected by a Use-After-Free vulnerability that could lead to arbitrary code execution.", 7.8, 6.8, "HIGH", "2021-09-29", "cpe:2.3:a:adobe:acrobat_reader_dc:20.007.20091:*:*:*:*:*:*:*"),
        ("CVE-2022-29072", "7-Zip through 21.07 on Windows allows privilege escalation and command execution because a file is misconfigured under Windows Help (.chm).", 7.8, 4.6, "HIGH", "2022-04-18", "cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*")
    ]
    
    for cve in sample_cves:
        try:
            cursor.execute("""
            INSERT OR IGNORE INTO cves (cve_id, description, cvss_v3_score, cvss_v2_score, severity, published_date, cpe23uri)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, cve)
        except Exception as e:
            print(f"Error seeding CVE {cve[0]}: {e}")
            
    conn.commit()
    print("Pre-seeding done successfully.")
