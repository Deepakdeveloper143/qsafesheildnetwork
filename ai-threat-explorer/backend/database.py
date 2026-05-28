import datetime

class DatabaseClient:
    """In‑memory mock database used by the Streamlit demo.
    It stores certificates, firewall scans and audit logs in Python lists.
    All methods return simple structures expected by the front‑end.
    """
    def __init__(self):
        self.certificates = []
        self.firewall_scans = []
        self.audit_logs = []
        # Flag used in the UI to decide between Supabase and local SQLite.
        self.use_supabase = False

    # ---------------------------------------------------------------------
    # Certificate handling
    # ---------------------------------------------------------------------
    def get_all_certificates(self):
        """Return a list of all certificate dictionaries."""
        return self.certificates

    def save_certificate(self, cert):
        """Add a new certificate to the store.
        A simple incremental integer ``id`` field is injected.
        """
        cert = cert.copy()
        cert_id = len(self.certificates) + 1
        cert["id"] = cert_id
        self.certificates.append(cert)
        return cert_id

    # ---------------------------------------------------------------------
    # Firewall scan handling
    # ---------------------------------------------------------------------
    def get_firewall_scans(self):
        """Return scans ordered newest‑first (the UI expects the first element to be the latest)."""
        return self.firewall_scans

    def save_firewall_scan(self, scan):
        """Store a firewall scan record. New scans are inserted at the front of the list."""
        self.firewall_scans.insert(0, scan)

    # ---------------------------------------------------------------------
    # Audit log handling
    # ---------------------------------------------------------------------
    def get_audit_logs(self):
        """Return the audit log entries in insertion order (newest last)."""
        return self.audit_logs

    def save_audit_log(self, action, details, actor="system"):
        """Append a new audit entry with a UTC timestamp.
        ``action`` is a short code (e.g., ``"FIREWALL_SCAN_COMPLETED"``).
        ``details`` is a human‑readable description.
        """
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "action": action,
            "details": details,
            "actor": actor,
        }
        self.audit_logs.append(entry)
        return entry
