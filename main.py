import uvicorn
import webbrowser
import threading
import time
import os
import sys

# Ensure current directory is in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import init_db

def open_browser():
    # Wait for server to boot up
    time.sleep(1.5)
    print("Launching browser dashboard at http://localhost:8000...")
    webbrowser.open("http://localhost:8000")

def main():
    # Initialize the local SQLite DB and seed with test data if it's new
    print("Initializing local SQLite databases...")
    init_db()
    
    # Run the browser opener in a separate thread so it doesn't block the server startup
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    # Launch uvicorn web server
    print("Starting SentinelCVE API server...")
    uvicorn.run("app.server:app", host="localhost", port=8000, reload=False)

if __name__ == "__main__":
    main()
