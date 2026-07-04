import sys
import os

# Ensure current directory is in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import init_db, get_db_connection
from app.scanner import get_installed_software
from app.matcher import find_best_cpe, get_vulnerabilities_for_cpe

def run_tests():
    print("=== SentinelCVE Verification Tests ===")
    
    # 1. Init DB
    print("\n[Test 1] Initializing database...")
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cpes")
    cpe_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cves")
    cve_count = cursor.fetchone()[0]
    print(f"Database statistics: {cpe_count} CPEs, {cve_count} CVEs loaded.")
    
    assert cpe_count > 0, "No CPEs loaded."
    assert cve_count > 0, "No CVEs loaded."
    print("Database initialization check: PASSED")
    
    # 2. Scanner Test
    print("\n[Test 2] Scanning local software assets...")
    software = get_installed_software()
    print(f"Scanned {len(software)} software installations.")
    assert len(software) > 0, "Scan returned empty."
    print("Local scanning check: PASSED")
    
    # 3. Matching Test
    print("\n[Test 3] Matching scanned assets against CPEs...")
    match_count = 0
    vuln_count = 0
    
    # Test a few registry items
    for item in software[:5]:
        name = item['name']
        pub = item['publisher']
        version = item['version']
        
        cpe_match = find_best_cpe(conn, name, pub, version)
        if cpe_match:
            match_count += 1
            print(f" - Found CPE match for '{name}' -> '{cpe_match['title']}' (Confidence: {cpe_match['confidence']:.2f})")
            
            cves = get_vulnerabilities_for_cpe(conn, cpe_match['cpe23uri'])
            if cves:
                vuln_count += 1
                print(f"   * Detected {len(cves)} vulnerability links (e.g. {cves[0]['cve_id']} - {cves[0]['severity']})")
        else:
            print(f" - No CPE match for '{name}'")
            
    # Test specific pre-seeded item to verify matching works
    print("\n[Test 4] Verifying matching end-to-end with specific known software (Google Chrome)...")
    chrome_match = find_best_cpe(conn, "Google Chrome", "Google LLC", "100.0.4896.60")
    if chrome_match:
        print(f" - Mapped Google Chrome to: {chrome_match['cpe23uri']}")
        chrome_cves = get_vulnerabilities_for_cpe(conn, chrome_match['cpe23uri'])
        print(f" - Found {len(chrome_cves)} CVEs for Chrome.")
        assert len(chrome_cves) > 0, "No CVEs found for Google Chrome"
        print("End-to-end matching check: PASSED")
    else:
        print("End-to-end matching check: FAILED (No match found)")
        assert False, "Failed to match Chrome"
            
    conn.close()
    
    print("\n=== Summary ===")
    print(f"Sample matches found: {match_count}")
    print(f"Sample vulnerabilities found: {vuln_count}")
    print("\nVerification check complete. Everything looks good!")

if __name__ == "__main__":
    run_tests()
