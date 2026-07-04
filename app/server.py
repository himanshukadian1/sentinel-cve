import os
import json
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime

from .database import get_db_connection
from .matcher import run_vulnerability_scan
from .updater import update_cpes, update_cves

app = FastAPI(title="SentinelCVE API", description="FastAPI server for CPE-CVE matcher")

# Global status tracker for background updates
update_status = {
    "status": "idle",
    "message": "System database is up to date.",
    "progress": 0,
    "last_updated": None
}

# Serve static web folder
web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")

@app.get("/api/scan")
def get_scan_results():
    """Runs a live scan of the local OS software and returns CVE matches."""
    try:
        results = run_vulnerability_scan()
        
        # Save scan history to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (timestamp, software_json) VALUES (?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), json.dumps(results))
        )
        conn.commit()
        conn.close()
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history")
def get_scan_history():
    """Fetches list of previous scans."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp FROM scans ORDER BY id DESC LIMIT 10")
        scans = cursor.fetchall()
        conn.close()
        return [dict(scan) for scan in scans]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history/{scan_id}")
def get_scan_by_id(scan_id: int):
    """Fetches a specific historical scan's data."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT software_json FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        return json.loads(row['software_json'])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_vulnerability_stats():
    """Calculates statistics based on the last scan."""
    try:
        # Run scan or get the last scan from DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT software_json FROM scans ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        
        if not row:
            # If no scan run yet, run one
            results = run_vulnerability_scan()
        else:
            results = json.loads(row['software_json'])
            
        cpes_count = 0
        total_cves = 0
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        scanned_count = len(results)
        
        for item in results:
            if item.get("cpe23uri"):
                cpes_count += 1
            for cve in item.get("cves", []):
                total_cves += 1
                sev = cve.get("severity", "UNKNOWN").upper()
                if sev in severities:
                    severities[sev] += 1
                else:
                    severities["UNKNOWN"] += 1
                    
        # Get count of total CPE definitions and CVE records in the database
        cursor.execute("SELECT COUNT(*) FROM cpes")
        db_cpes = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves")
        db_cves = cursor.fetchone()[0]
        conn.close()
        
        return {
            "scanned_count": scanned_count,
            "matched_cpes_count": cpes_count,
            "total_vulnerabilities": total_cves,
            "severity_distribution": severities,
            "db_cpes_total": db_cpes,
            "db_cves_total": db_cves
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def run_db_update():
    """Background task to fetch NIST data."""
    global update_status
    try:
        update_status["status"] = "updating"
        
        def progress_cb(msg):
            update_status["message"] = msg
            
        cpe_count = update_cpes(progress_cb)
        cve_count = update_cves(progress_cb)
        
        update_status["status"] = "idle"
        update_status["message"] = f"Finished successfully. Added {cpe_count} CPEs and {cve_count} CVE links."
        update_status["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        update_status["status"] = "failed"
        update_status["message"] = f"Update failed: {str(e)}"

@app.post("/api/update_db")
def trigger_db_update(background_tasks: BackgroundTasks):
    """Triggers an asynchronous update of the local CPE/CVE database from NIST."""
    global update_status
    if update_status["status"] == "updating":
        return {"message": "Update already in progress"}
        
    background_tasks.add_task(run_db_update)
    return {"message": "Update started in the background"}

@app.get("/api/update_db/status")
def get_db_update_status():
    """Returns status of database updater."""
    return update_status

# Serve index.html as fallback
@app.get("/")
def get_index():
    return FileResponse(os.path.join(web_dir, "index.html"))

# Serve other static files (like style.css, app.js)
if os.path.exists(web_dir):
    app.mount("/", StaticFiles(directory=web_dir), name="static")
