import os
import sqlite3
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

log = logging.getLogger("venafi.database")

class DatabaseClient:
    """
    Unified database client that connects to Supabase if configured,
    or falls back to a local SQLite database.
    """
    def __init__(self, supabase_url: Optional[str] = None, supabase_key: Optional[str] = None):
        self.supabase_url = supabase_url or os.getenv("SUPABASE_URL")
        self.supabase_key = supabase_key or os.getenv("SUPABASE_KEY")
        self.use_supabase = bool(self.supabase_url and self.supabase_key and "your-supabase" not in self.supabase_url)
        self.sqlite_path = "pki_audit.db"
        self.client = None

        if self.use_supabase:
            try:
                from supabase import create_client, Client
                self.client = create_client(self.supabase_url, self.supabase_key)
                log.info("Successfully connected to Supabase DB.")
            except Exception as e:
                log.error(f"Failed to initialize Supabase client: {e}. Falling back to SQLite.")
                self.use_supabase = False

        if not self.use_supabase:
            log.info(f"Using local SQLite database at {self.sqlite_path}")
            self._init_sqlite()

    def _init_sqlite(self):
        """Initialize local SQLite tables if they do not exist."""
        conn = sqlite3.connect(self.sqlite_path)
        cursor = conn.cursor()
        
        # Certificates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                issuer TEXT,
                expiry_date TEXT,
                days_remaining INTEGER,
                risk_severity TEXT,
                status TEXT,
                public_key TEXT,
                created_at TEXT
            )
        """)
        
        # Firewall scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_scans (
                id TEXT PRIMARY KEY,
                target_host TEXT,
                ip_address TEXT,
                scan_time TEXT,
                open_ports TEXT,
                blocked_ports TEXT,
                is_compliant INTEGER,
                scan_duration_s REAL
            )
        """)
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                action TEXT,
                details TEXT,
                actor TEXT
            )
        """)

        # Quantum audits table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quantum_audits (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                cert_id TEXT,
                cert_name TEXT,
                quantum_risk_score INTEGER,
                estimated_break_time_years TEXT,
                recommended_algorithm TEXT,
                key_type TEXT,
                key_size INTEGER
            )
        """)
        
        conn.commit()

        # Migration: ensure expected columns exist on existing DB files
        try:
            cursor.execute("PRAGMA table_info(quantum_audits)")
            existing_cols = [r[1] for r in cursor.fetchall()]
            # Add missing columns safely
            if 'key_type' not in existing_cols:
                cursor.execute("ALTER TABLE quantum_audits ADD COLUMN key_type TEXT")
            if 'key_size' not in existing_cols:
                cursor.execute("ALTER TABLE quantum_audits ADD COLUMN key_size INTEGER")
            conn.commit()
        except Exception as e:
            log.error(f"SQLite migration error for quantum_audits: {e}")

        conn.close()

    # --- Certificates ---
    def save_certificate(self, cert: Dict[str, Any]) -> bool:
        if not cert.get("id"):
            cert["id"] = str(uuid.uuid4())
        if not cert.get("created_at"):
            cert["created_at"] = datetime.now(timezone.utc).isoformat()

        if self.use_supabase:
            try:
                res = self.client.table("certificates").upsert(cert).execute()
                return True
            except Exception as e:
                log.error(f"Supabase save_certificate error: {e}")
                # fallback save to SQLite
                self._save_certificate_sqlite(cert)
                return True
        else:
            return self._save_certificate_sqlite(cert)

    def _save_certificate_sqlite(self, cert: Dict[str, Any]) -> bool:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO certificates 
                (id, name, issuer, expiry_date, days_remaining, risk_severity, status, public_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cert["id"], cert["name"], cert.get("issuer"), cert.get("expiry_date"),
                cert.get("days_remaining"), cert.get("risk_severity"), cert.get("status"),
                cert.get("public_key"), cert["created_at"]
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.error(f"SQLite save_certificate error: {e}")
            return False

    def get_all_certificates(self) -> List[Dict[str, Any]]:
        if self.use_supabase:
            try:
                res = self.client.table("certificates").select("*").execute()
                return res.data
            except Exception as e:
                log.error(f"Supabase get_all_certificates error: {e}. Reading SQLite fallback.")
                return self._get_all_certificates_sqlite()
        else:
            return self._get_all_certificates_sqlite()

    def _get_all_certificates_sqlite(self) -> List[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM certificates ORDER BY expiry_date ASC")
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            log.error(f"SQLite get_all_certificates error: {e}")
            return []

    # --- Firewall Scans ---
    def save_firewall_scan(self, scan: Dict[str, Any]) -> bool:
        if not scan.get("id"):
            scan["id"] = str(uuid.uuid4())
        if not scan.get("scan_time"):
            scan["scan_time"] = datetime.now(timezone.utc).isoformat()

        # Serialize lists to string for unified storage
        open_ports_str = json.dumps(scan.get("open_ports", []))
        blocked_ports_str = json.dumps(scan.get("blocked_ports", []))
        is_compliant_val = 1 if scan.get("is_compliant", False) else 0

        if self.use_supabase:
            try:
                # We write as structured JSON to Supabase
                data = {
                    "id": scan["id"],
                    "target_host": scan.get("target_host"),
                    "ip_address": scan.get("ip_address"),
                    "scan_time": scan["scan_time"],
                    "open_ports": scan.get("open_ports", []),
                    "blocked_ports": scan.get("blocked_ports", []),
                    "is_compliant": scan.get("is_compliant", False),
                    "scan_duration_s": scan.get("scan_duration_s", 0.0)
                }
                self.client.table("firewall_scans").upsert(data).execute()
                return True
            except Exception as e:
                log.error(f"Supabase save_firewall_scan error: {e}")
                self._save_firewall_scan_sqlite(scan, open_ports_str, blocked_ports_str, is_compliant_val)
                return True
        else:
            return self._save_firewall_scan_sqlite(scan, open_ports_str, blocked_ports_str, is_compliant_val)

    def _save_firewall_scan_sqlite(self, scan: Dict[str, Any], open_ports: str, blocked_ports: str, is_compliant: int) -> bool:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO firewall_scans
                (id, target_host, ip_address, scan_time, open_ports, blocked_ports, is_compliant, scan_duration_s)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan["id"], scan.get("target_host"), scan.get("ip_address"), scan["scan_time"],
                open_ports, blocked_ports, is_compliant, scan.get("scan_duration_s", 0.0)
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.error(f"SQLite save_firewall_scan error: {e}")
            return False

    def get_firewall_scans(self) -> List[Dict[str, Any]]:
        if self.use_supabase:
            try:
                res = self.client.table("firewall_scans").select("*").execute()
                return res.data
            except Exception as e:
                log.error(f"Supabase get_firewall_scans error: {e}. Reading SQLite fallback.")
                return self._get_firewall_scans_sqlite()
        else:
            return self._get_firewall_scans_sqlite()

    def _get_firewall_scans_sqlite(self) -> List[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM firewall_scans ORDER BY scan_time DESC")
            rows = cursor.fetchall()
            conn.close()
            
            result = []
            for r in rows:
                d = dict(r)
                # Deserialize fields
                try:
                    d["open_ports"] = json.loads(d["open_ports"])
                except Exception:
                    d["open_ports"] = []
                try:
                    d["blocked_ports"] = json.loads(d["blocked_ports"])
                except Exception:
                    d["blocked_ports"] = []
                d["is_compliant"] = bool(d["is_compliant"])
                result.append(d)
            return result
        except Exception as e:
            log.error(f"SQLite get_firewall_scans error: {e}")
            return []

    # --- Audit Logs ---
    def save_audit_log(self, action: str, details: str, actor: str = "System Agent") -> bool:
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        data = {
            "id": log_id,
            "timestamp": timestamp,
            "action": action,
            "details": details,
            "actor": actor
        }

        if self.use_supabase:
            try:
                self.client.table("audit_logs").insert(data).execute()
                return True
            except Exception as e:
                log.error(f"Supabase save_audit_log error: {e}")
                self._save_audit_log_sqlite(data)
                return True
        else:
            return self._save_audit_log_sqlite(data)

    def _save_audit_log_sqlite(self, data: Dict[str, Any]) -> bool:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (id, timestamp, action, details, actor)
                VALUES (?, ?, ?, ?, ?)
            """, (data["id"], data["timestamp"], data["action"], data["details"], data["actor"]))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.error(f"SQLite save_audit_log error: {e}")
            return False

    def get_audit_logs(self) -> List[Dict[str, Any]]:
        if self.use_supabase:
            try:
                res = self.client.table("audit_logs").select("*").order("timestamp", desc=True).execute()
                return res.data
            except Exception as e:
                log.error(f"Supabase get_audit_logs error: {e}. Reading SQLite fallback.")
                return self._get_audit_logs_sqlite()
        else:
            return self._get_audit_logs_sqlite()

    def _get_audit_logs_sqlite(self) -> List[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            log.error(f"SQLite get_audit_logs error: {e}")
            return []

    # --- Quantum Audits ---
    def save_quantum_audit(self, audit: Dict[str, Any]) -> bool:
        if not audit.get("id"):
            audit["id"] = str(uuid.uuid4())
        if not audit.get("timestamp"):
            audit["timestamp"] = datetime.now(timezone.utc).isoformat()

        if self.use_supabase:
            try:
                self.client.table("quantum_audits").upsert(audit).execute()
                return True
            except Exception as e:
                log.error(f"Supabase save_quantum_audit error: {e}")
                self._save_quantum_audit_sqlite(audit)
                return True
        else:
            return self._save_quantum_audit_sqlite(audit)

    def _save_quantum_audit_sqlite(self, audit: Dict[str, Any]) -> bool:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO quantum_audits
                (id, timestamp, cert_id, cert_name, quantum_risk_score, estimated_break_time_years, recommended_algorithm, key_type, key_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                audit["id"], audit["timestamp"], audit.get("cert_id"), audit.get("cert_name"),
                audit.get("quantum_risk_score"), audit.get("estimated_break_time_years"),
                audit.get("recommended_algorithm"), audit.get("key_type"), audit.get("key_size")
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.error(f"SQLite save_quantum_audit error: {e}")
            return False

    def get_quantum_audits(self) -> List[Dict[str, Any]]:
        if self.use_supabase:
            try:
                res = self.client.table("quantum_audits").select("*").execute()
                return res.data
            except Exception as e:
                log.error(f"Supabase get_quantum_audits error: {e}. Reading SQLite fallback.")
                return self._get_quantum_audits_sqlite()
        else:
            return self._get_quantum_audits_sqlite()

    def _get_quantum_audits_sqlite(self) -> List[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(self.sqlite_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quantum_audits ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            log.error(f"SQLite get_quantum_audits error: {e}")
            return []
