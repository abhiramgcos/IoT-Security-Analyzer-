
import sqlite3
import json
from typing import List, Dict, Optional
from datetime import datetime
from backend.config import settings
from backend.logger import Logger

logger = Logger('database').get_logger()

class Database:
    def __init__(self):
        self.db_path = settings.DB_PATH
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initialize database schema"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Devices table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    device_type TEXT,
                    manufacturer TEXT,
                    model TEXT,
                    cpe TEXT,
                    open_ports TEXT,  -- JSON stored as text
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    status TEXT
                )
                ''')
                
                # Vulnerabilities table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    cve_id TEXT,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    remediation TEXT,
                    component TEXT,
                    FOREIGN KEY(device_id) REFERENCES devices(id)
                )
                ''')
                
                # Schema Migration: Add cpe and component columns if they don't exist
                try:
                    cursor.execute("ALTER TABLE devices ADD COLUMN cpe TEXT")
                except sqlite3.OperationalError:
                    pass # Column likely exists
                
                try:
                    cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN component TEXT")
                except sqlite3.OperationalError:
                     pass

                conn.commit()
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")

    def get_all_devices(self) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices")
            rows = cursor.fetchall()
            devices = []
            for row in rows:
                d = dict(row)
                
                # Handle open_ports - can be JSON string, empty string, or None
                ports_value = d.get('open_ports')
                if ports_value:
                    if isinstance(ports_value, str):
                        try:
                            d['open_ports'] = json.loads(ports_value)
                        except (json.JSONDecodeError, ValueError):
                            d['open_ports'] = []
                    elif isinstance(ports_value, list):
                        d['open_ports'] = ports_value
                    else:
                        d['open_ports'] = []
                else:
                    d['open_ports'] = []
                    
                # Ensure validation compliance - replace None with safe defaults
                d['mac_address'] = d.get('mac_address') or "Unknown"
                d['hostname'] = d.get('hostname') or "Unknown"
                d['device_type'] = d.get('device_type') or "Unknown"
                d['manufacturer'] = d.get('manufacturer') or "Unknown"
                d['status'] = d.get('status') or "unknown"
                d['first_seen'] = d.get('first_seen') or ""
                d['last_seen'] = d.get('last_seen') or ""
                
                devices.append(d)
            return devices

    def get_device(self, ip_address: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                if d['open_ports']:
                    d['open_ports'] = json.loads(d['open_ports'])
                return d
            return None

    def upsert_device(self, device_data: Dict):
        """Insert or update device"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if exists
                cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (device_data['ip_address'],))
                existing = cursor.fetchone()
                
                now = datetime.now().isoformat()
                ports_json = json.dumps(device_data.get('open_ports', []))
                
                if existing:
                    cursor.execute('''
                    UPDATE devices SET 
                        mac_address=?, hostname=?, device_type=?, 
                        manufacturer=?, model=?, cpe=?, open_ports=?, 
                        last_seen=?, status=?
                    WHERE ip_address=?
                    ''', (
                        device_data.get('mac_address'),
                        device_data.get('hostname'),
                        device_data.get('device_type'),
                        device_data.get('manufacturer'),
                        device_data.get('model'),
                        device_data.get('cpe'),
                        ports_json,
                        now,
                        'online',
                        device_data['ip_address']
                    ))
                else:
                    cursor.execute('''
                    INSERT INTO devices (
                        ip_address, mac_address, hostname, device_type,
                        manufacturer, model, cpe, open_ports, first_seen,
                        last_seen, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device_data['ip_address'],
                        device_data.get('mac_address'),
                        device_data.get('hostname'),
                        device_data.get('device_type'),
                        device_data.get('manufacturer'),
                        device_data.get('model'),
                        device_data.get('cpe'),
                        ports_json,
                        now,
                        now,
                        'online'
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error upserting device: {e}")
            
    def get_device_vulnerabilities(self, device_id: int) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerabilities WHERE device_id = ?", (device_id,))
            return [dict(row) for row in cursor.fetchall()]

    def add_vulnerability(self, device_id: int, vuln: Dict):
        """Add a vulnerability to a device"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if exists to avoid duplicates
                cursor.execute('''
                SELECT id FROM vulnerabilities 
                WHERE device_id=? AND cve_id=?
                ''', (device_id, vuln.get('cve_id')))
                
                if not cursor.fetchone():
                    cursor.execute('''
                    INSERT INTO vulnerabilities (
                        device_id, cve_id, description, severity, 
                        cvss_score, remediation, component
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device_id,
                        vuln.get('cve_id'),
                        vuln.get('description'),
                        vuln.get('severity'),
                        vuln.get('cvss_score'),
                        vuln.get('remediation'),
                        vuln.get('component')
                    ))
                    conn.commit()
        except Exception as e:
            logger.error(f"Error adding vulnerability: {e}")
    
    def clear_all_data(self):
        """Clear all data from all tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM vulnerabilities")
                cursor.execute("DELETE FROM devices")
                conn.commit()
                logger.info("All data cleared from database")
                return True
        except Exception as e:
            logger.error(f"Error clearing data: {e}")
            return False
