import os
import gzip
import xml.etree.ElementTree as ET
import requests
import json
import sqlite3
from .database import get_db_connection

CPE_DICT_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
CVE_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"

def update_cpes(progress_callback=None):
    """Downloads the official NIST CPE dictionary XML, parses, and updates the local DB."""
    temp_gz = "cpe_dict.xml.gz"
    
    if progress_callback:
        progress_callback("Downloading official NIST CPE dictionary...")
        
    response = requests.get(CPE_DICT_URL, stream=True)
    if response.status_code != 200:
        raise Exception(f"Failed to download CPE dictionary: HTTP {response.status_code}")
        
    with open(temp_gz, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                
    if progress_callback:
        progress_callback("Extracting and parsing CPE dictionary (this may take a few minutes)...")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # We read the gzipped xml file
    count = 0
    with gzip.open(temp_gz, 'rb') as f:
        # We parse the XML tree in an iterative/streaming fashion to keep memory footprint low
        context = ET.iterparse(f, events=('end',))
        
        cpe_batch = []
        
        for event, elem in context:
            # Look for cpe-item elements
            if elem.tag.endswith('cpe-item'):
                name = elem.attrib.get('name') # cpe20
                cpe23uri = None
                title = None
                
                # Extract children: title and cpe-23:cpe23-item
                for child in elem:
                    if child.tag.endswith('title') and child.attrib.get('{http://www.w3.org/XML/1998/namespace}lang') == 'en':
                        title = child.text
                    elif child.tag.endswith('cpe23-item'):
                        cpe23uri = child.attrib.get('name')
                        
                if cpe23uri:
                    # Parse CPE elements
                    # cpe:2.3:a:vendor:product:version:...
                    parts = cpe23uri.split(':')
                    if len(parts) > 5:
                        part = parts[2]
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5]
                        
                        if not title:
                            title = f"{vendor} {product} {version}"
                            
                        cpe_batch.append((title, cpe23uri, part, vendor, product, version))
                        count += 1
                        
                # Insert in batches of 5000
                if len(cpe_batch) >= 5000:
                    cursor.executemany("""
                        INSERT OR IGNORE INTO cpes (title, cpe23uri, part, vendor, product, version)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, cpe_batch)
                    conn.commit()
                    cpe_batch = []
                    if progress_callback:
                        progress_callback(f"Parsed {count} CPE records...")
                        
                # Clear elements to free up memory
                elem.clear()
                
        # Insert any remaining records
        if cpe_batch:
            cursor.executemany("""
                INSERT OR IGNORE INTO cpes (title, cpe23uri, part, vendor, product, version)
                VALUES (?, ?, ?, ?, ?, ?)
            """, cpe_batch)
            conn.commit()
            
    # Clean up temp file
    if os.path.exists(temp_gz):
        os.remove(temp_gz)
        
    if progress_callback:
        progress_callback(f"Successfully loaded {count} CPE definitions into database.")
        
    return count

def update_cves(progress_callback=None):
    """Downloads recent CVE feeds, parses and saves to DB."""
    temp_gz = "cve_recent.json.gz"
    
    if progress_callback:
        progress_callback("Downloading recent NIST NVD CVE feed...")
        
    response = requests.get(CVE_RECENT_URL, stream=True)
    if response.status_code != 200:
        raise Exception(f"Failed to download CVE feed: HTTP {response.status_code}")
        
    with open(temp_gz, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                
    if progress_callback:
        progress_callback("Parsing and loading CVEs into database...")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    count = 0
    with gzip.open(temp_gz, 'rt', encoding='utf-8') as f:
        data = json.load(f)
        cve_items = data.get('CVE_Items', [])
        
        cve_batch = []
        for item in cve_items:
            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            descriptions = item.get('cve', {}).get('description', {}).get('description_data', [])
            description = descriptions[0].get('value') if descriptions else ""
            
            published_date = item.get('publishedDate', '')[:10] # YYYY-MM-DD
            
            # Scores
            impact = item.get('impact', {})
            cvss_v3_score = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
            cvss_v2_score = impact.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
            severity = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity') or "UNKNOWN"
            
            # Affected CPEs
            nodes = item.get('configurations', {}).get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpe_match', [])
                # Or look recursively in children nodes
                if not cpe_matches and node.get('children'):
                    for child in node.get('children', []):
                        cpe_matches.extend(child.get('cpe_match', []))
                        
                for match in cpe_matches:
                    cpe23uri = match.get('cpe23Uri')
                    if cpe23uri:
                        cve_batch.append((
                            cve_id, description, cvss_v3_score, cvss_v2_score,
                            severity, published_date, cpe23uri
                        ))
                        count += 1
                        
            if len(cve_batch) >= 1000:
                cursor.executemany("""
                    INSERT OR IGNORE INTO cves (
                        cve_id, description, cvss_v3_score, cvss_v2_score, severity, published_date, cpe23uri
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, cve_batch)
                conn.commit()
                cve_batch = []
                if progress_callback:
                    progress_callback(f"Parsed {count} CVE links...")
                    
        if cve_batch:
            cursor.executemany("""
                INSERT OR IGNORE INTO cves (
                    cve_id, description, cvss_v3_score, cvss_v2_score, severity, published_date, cpe23uri
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, cve_batch)
            conn.commit()
            
    if os.path.exists(temp_gz):
        os.remove(temp_gz)
        
    if progress_callback:
        progress_callback(f"Successfully loaded {count} CVE links into database.")
        
    return count
