
import sys
import os
import json
from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Optional

# Mock Pydantic Model from scanner.py
class DeviceResponse(BaseModel):
    id: int
    ip_address: str
    mac_address: str
    hostname: str
    device_type: str
    manufacturer: str
    model: Optional[str]
    open_ports: List[int]
    first_seen: str
    last_seen: str
    status: str

# Replicate Database logic partially to see what it returns
# We assume the file is at: /var/home/cos777nnn/firmai_v3/iot_security_analyzer/data/devices.db
DB_PATH = "/var/home/cos777nnn/firmai_v3/iot_security_analyzer/data/devices.db"

import sqlite3

def test_fetch_and_validate():
    print(f"Connecting to {DB_PATH}")
    if not os.path.exists(DB_PATH):
        print("Database file not found!")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM devices")
        rows = cursor.fetchall()
        print(f"Found {len(rows)} rows.")
        
        for row in rows:
            d = dict(row)
            print(f"Processing Row ID: {d.get('id')}")
            
            # Simulate database.py logic
            if d.get('open_ports'):
                try:
                    d['open_ports'] = json.loads(d['open_ports'])
                except:
                    d['open_ports'] = []
            else:
                d['open_ports'] = []
            
            # Print data before validation
            print(f"Data: {d}")
            
            try:
                # Attempt validation
                model = DeviceResponse(**d)
                print("Validation Success")
            except Exception as e:
                print(f"Validation FAILED: {e}")

    except Exception as e:
        print(f"SQL Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    test_fetch_and_validate()
