import datetime
import uuid
from typing import List, Dict

# Import the DatabaseClient for persistence
try:
    from .database import DatabaseClient
except Exception:
    DatabaseClient = None

class CertificateLifecycleManager:
    """Very light‑weight mock CLM (Certificate Lifecycle Management).
    It stores certificates in the in‑memory DatabaseClient and provides the
    subset of operations referenced by the Streamlit UI.
    """

    def __init__(self, db_client: DatabaseClient):
        self.db = db_client

    def _make_cert_dict(self, common_name: str, key_size: int = 2048, validity_days: int = 365) -> Dict:
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = now + datetime.timedelta(days=validity_days)
        cert = {
            "id": str(uuid.uuid4()),
            "name": common_name,
            "issuer": "Mock CA",
            "expiry_date": expiry.isoformat(),
            "days_remaining": (expiry - now).days,
            "risk_severity": "LOW" if validity_days > 180 else "HIGH",
            "status": "ACTIVE",
            "public_key": f"-----BEGIN PUBLIC KEY-----\nMockKey{key_size}\n-----END PUBLIC KEY-----",
            "created_at": now.isoformat(),
        }
        return cert

    def issue_new_certificate(self, common_name: str, key_size: int = 2048, validity_days: int = 365) -> Dict:
        """Create a new dummy certificate and persist it."""
        cert = self._make_cert_dict(common_name, key_size, validity_days)
        if self.db:
            self.db.save_certificate(cert)
        return cert

    def get_expiring_certificates_report(self, days_threshold: int = 45) -> List[Dict]:
        """Return certificates whose days_remaining ≤ threshold and are ACTIVE.
        UI expects fields: name, days_remaining, expiry_date, risk_severity.
        """
        certs = self.db.get_all_certificates() if self.db else []
        report = [
            {
                "name": c["name"],
                "days_remaining": c["days_remaining"],
                "expiry_date": c["expiry_date"],
                "risk_severity": c["risk_severity"],
            }
            for c in certs
            if c["status"] == "ACTIVE" and c["days_remaining"] <= days_threshold
        ]
        return report

    def renew_certificate(self, cert_id: str) -> bool:
        """Extend expiry by 365 days for the given certificate id.
        Returns True on success.
        """
        certs = self.db.get_all_certificates() if self.db else []
        for cert in certs:
            if cert["id"] == cert_id:
                now = datetime.datetime.now(datetime.timezone.utc)
                new_expiry = now + datetime.timedelta(days=365)
                cert["expiry_date"] = new_expiry.isoformat()
                cert["days_remaining"] = (new_expiry - now).days
                # In a real DB we would update; here we replace the whole list
                # for simplicity by re‑saving all certificates.
                self.db.certificates = [c if c["id"] != cert_id else cert for c in self.db.certificates]
                return True
        return False

    def revoke_certificate(self, cert_id: str) -> bool:
        """Mark a certificate as REVOKED.
        Returns True if the certificate was found.
        """
        certs = self.db.get_all_certificates() if self.db else []
        for cert in certs:
            if cert["id"] == cert_id:
                cert["status"] = "REVOKED"
                self.db.certificates = [c if c["id"] != cert_id else cert for c in self.db.certificates]
                return True
        return False

    def scan_network_target(self, host: str, port: int) -> Dict:
        """Placeholder for a network‑certificate discovery.
        Returns a minimal dict that matches UI expectations.
        """
        # Dummy data – in a real implementation we would perform TLS handshake.
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = now + datetime.timedelta(days=180)
        return {
            "name": f"{host}:{port}",
            "issuer": "Mock CA",
            "expiry_date": expiry.isoformat(),
            "days_remaining": (expiry - now).days,
        }

# End of backend/pki.py
