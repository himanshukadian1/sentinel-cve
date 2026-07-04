import re
import sqlite3
from difflib import SequenceMatcher
from .database import get_db_connection

def clean_string(s):
    """Normalize and clean string for matching."""
    if not s:
        return ""
    # Lowercase, replace special chars with space, remove inc, corp, corporation
    s = s.lower()
    s = re.sub(r'\b(corp(oration)?|inc(orporated)?|ltd|limited|llc|gmbh|co(mpany)?|software|technologies|group)\b', '', s)
    s = re.sub(r'[^a-z0-9 ]', ' ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def get_similarity(s1, s2):
    """Returns ratio of similarity between two strings."""
    return SequenceMatcher(None, s1, s2).ratio()

def find_best_cpe(conn, name, publisher, version):
    """
    Searches the database for the best matching CPE for the scanned software.
    Uses SQLite FTS5 for rapid candidate lookup, followed by difflib sorting.
    """
    cursor = conn.cursor()
    
    clean_name = clean_string(name)
    clean_pub = clean_string(publisher)
    
    # Combined search query tokens
    search_tokens = list(dict.fromkeys(clean_name.split() + clean_pub.split()))
    if not search_tokens:
        return None
        
    # Match using FTS5 (FTS5 match search)
    fts_query = " OR ".join([f"{token}*" for token in search_tokens])
    
    cursor.execute("""
        SELECT cpes.id as id, cpes.title, cpes.cpe23uri, cpes.vendor, cpes.product, cpes.version
        FROM cpes_fts
        JOIN cpes ON cpes.id = cpes_fts.rowid
        WHERE cpes_fts MATCH ?
        LIMIT 100
    """, (fts_query,))
    
    candidates = cursor.fetchall()
    
    # Fallback to broad LIKE search if FTS5 yields no results
    if not candidates:
        like_patterns = [f"%{token}%" for token in search_tokens]
        if like_patterns:
            cursor.execute("""
                SELECT id, title, cpe23uri, vendor, product, version
                FROM cpes
                WHERE vendor LIKE ? OR product LIKE ?
                LIMIT 50
            """, (like_patterns[0], like_patterns[0]))
            candidates = cursor.fetchall()
            
    if not candidates:
        return None
        
    best_candidate = None
    highest_score = -1.0
    
    target_comp = f"{clean_pub} {clean_name}"
    
    for candidate in candidates:
        cand_vendor = clean_string(candidate['vendor'])
        cand_product = clean_string(candidate['product'])
        
        # Calculate similarity score based on vendor and product
        cand_comp = f"{cand_vendor} {cand_product}"
        
        # We compute both quick_ratio and ratio, weights favor product match
        score = get_similarity(target_comp, cand_comp)
        
        # Boost score if publisher or name is directly contained
        if cand_product in clean_name:
            score += 0.2
        if cand_vendor in clean_pub or cand_vendor in clean_name:
            score += 0.1
            
        if score > highest_score:
            highest_score = score
            best_candidate = candidate
            
    # We set a similarity threshold (e.g. 0.35)
    if highest_score < 0.35 or not best_candidate:
        return None
        
    # Format a specific CPE URI for this version of the software
    cpe_parts = best_candidate['cpe23uri'].split(':')
    # Update version (index 5) with scanned version if scanned version exists
    if version and len(cpe_parts) > 5:
        cpe_parts[5] = version
        
    matched_cpe_uri = ":".join(cpe_parts)
    
    return {
        "title": best_candidate['title'],
        "cpe23uri": matched_cpe_uri,
        "vendor": best_candidate['vendor'],
        "product": best_candidate['product'],
        "version": version or best_candidate['version'],
        "confidence": min(1.0, highest_score)
    }

def get_vulnerabilities_for_cpe(conn, cpe23uri):
    """Fetches list of CVEs for a specific CPE URI."""
    cursor = conn.cursor()
    
    # Check for exact matches
    cursor.execute("""
        SELECT cve_id, description, cvss_v3_score, cvss_v2_score, severity, published_date
        FROM cves
        WHERE cpe23uri = ?
    """, (cpe23uri,))
    cves = cursor.fetchall()
    
    # Fallback to wildcard search (matching product and version pattern if needed)
    if not cves:
        # e.g. cpe:2.3:a:google:chrome:100.0.4896.60:*:*:*:*:*:*:* -> matches product google:chrome
        parts = cpe23uri.split(':')
        if len(parts) > 5:
            prefix = ":".join(parts[:5]) + ":"
            cursor.execute("""
                SELECT cve_id, description, cvss_v3_score, cvss_v2_score, severity, published_date
                FROM cves
                WHERE cpe23uri LIKE ? AND cpe23uri LIKE ?
            """, (f"{prefix}%", f"%:{parts[5]}:%"))
            cves = cursor.fetchall()
            
    return [dict(cve) for cve in cves]

def run_vulnerability_scan():
    """Runs scanning and matching on all installed software."""
    from .scanner import get_installed_software
    
    conn = get_db_connection()
    installed = get_installed_software()
    results = []
    
    for item in installed:
        name = item['name']
        pub = item['publisher']
        version = item['version']
        
        cpe_match = find_best_cpe(conn, name, pub, version)
        
        cves = []
        if cpe_match:
            cves = get_vulnerabilities_for_cpe(conn, cpe_match['cpe23uri'])
            
        results.append({
            "scanned_name": name,
            "scanned_publisher": pub,
            "scanned_version": version,
            "cpe_title": cpe_match['title'] if cpe_match else "No match found",
            "cpe23uri": cpe_match['cpe23uri'] if cpe_match else None,
            "confidence": round(cpe_match['confidence'] * 100, 1) if cpe_match else 0,
            "cves": cves,
            "cves_count": len(cves)
        })
        
    conn.close()
    return results
