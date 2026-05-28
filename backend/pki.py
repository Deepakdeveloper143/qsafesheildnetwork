import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from backend.database import DatabaseClient
from backend.hsm import EntrustShieldHSMSimulator

log = logging.getLogger("venafi.pki")

class CertificateLifecycleManager:
    """
    Manages discovery, inventory, status tracking, renewal, and revocation of SSL/TLS certificates.
    """
    def __init__(self, db_client: DatabaseClient, hsm_simulator: EntrustShieldHSMSimulator):
        self.db = db_client
        self.hsm = hsm_simulator

    # --- Discovery & Scanning ---
    def scan_network_target(self, host: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Connects to a host:port via TLS, retrieves the certificate,
        parses its metadata, and saves it to the inventory.
        """
        log.info(f"Scanning target {host}:{port} for TLS/SSL certificate...")
        try:
            context = ssl.create_default_context()
            # Disable verification so we can scan expired or self-signed certs too
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        log.warning(f"No certificate retrieved from {host}:{port}")
                        return None
                    
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    cert_data = self._parse_certificate(cert, host)
                    
                    # Save to DB
                    self.db.save_certificate(cert_data)
                    self.db.save_audit_log(
                        action="CERTIFICATE_DISCOVERED",
                        details=f"Discovered TLS certificate for {cert_data['name']} on {host}:{port}. Expiring {cert_data['expiry_date']}",
                        actor="PKI Scanner"
                    )
                    return cert_data
        except Exception as e:
            log.error(f"Failed to scan certificate on {host}:{port} - {e}")
            self.db.save_audit_log(
                action="CERTIFICATE_SCAN_FAILED",
                details=f"Failed to connect and parse certificate from {host}:{port} - {str(e)}",
                actor="PKI Scanner"
            )
            return None

    def _parse_certificate(self, cert: x509.Certificate, target_host: str) -> Dict[str, Any]:
        """Convert a cryptography x509 Certificate object into a DB-friendly dictionary."""
        subject = cert.subject
        issuer = cert.issuer
        
        # Get common names
        try:
            cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            cn = target_host
            
        try:
            issuer_cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            issuer_cn = "Unknown Issuer"

        # Calculate validity
        expiry = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_remaining = (expiry - now).days
        
        status = "ACTIVE"
        if days_remaining < 0:
            status = "EXPIRED"
            risk_severity = "CRITICAL"
        elif days_remaining <= 15:
            risk_severity = "CRITICAL"
        elif days_remaining <= 45:
            risk_severity = "HIGH"
        else:
            risk_severity = "LOW"

        # Extract public key PEM
        pub_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return {
            "name": cn,
            "issuer": issuer_cn,
            "expiry_date": expiry.isoformat(),
            "days_remaining": max(days_remaining, 0),
            "risk_severity": risk_severity,
            "status": status,
            "public_key": pub_key_pem
        }

    # --- HSM-Backed Certificate Lifecycle ---
    def issue_new_certificate(self, common_name: str, key_size: int = 2048, validity_days: int = 365) -> Dict[str, Any]:
        """Simulates requesting keys + CSR, signing via HSM, and storing it."""
        try:
            # Step 1: Generate keys & CSR
            log.info(f"Generating private key and CSR for {common_name}")
            client_key, csr_pem = self.hsm.generate_client_keys_and_csr(common_name, key_size=key_size)
            
            # Step 2: Sign CSR inside HSM
            log.info(f"Signing CSR inside the HSM...")
            cert_pem, root_pem = self.hsm.sign_csr(csr_pem, expiry_days=validity_days)
            
            # Step 3: Parse and Save Certificate
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            cert_data = self._parse_certificate(cert, common_name)
            
            # Save it
            self.db.save_certificate(cert_data)
            self.db.save_audit_log(
                action="CERTIFICATE_ISSUED",
                details=f"Issued certificate for {common_name} with key size {key_size} signed by HSM Root.",
                actor="PKI Manager"
            )
            return cert_data
        except Exception as e:
            log.error(f"Failed to issue certificate: {e}")
            raise e

    def renew_certificate(self, cert_id: str) -> bool:
        """Find a certificate, generate a new key pair and CSR, sign via HSM, and update database."""
        try:
            certs = self.db.get_all_certificates()
            target_cert = next((c for c in certs if c["id"] == cert_id), None)
            if not target_cert:
                log.error(f"Certificate ID {cert_id} not found in inventory.")
                return False

            common_name = target_cert["name"]
            log.info(f"Renewing certificate for {common_name}...")
            
            # Generate and sign new cert
            new_cert_data = self.issue_new_certificate(common_name)
            
            # Delete old cert and insert new (or overwrite)
            # For simplicity, we just mark old as REVOKED/REPLACED and save the new one
            target_cert["status"] = "REVOKED"
            target_cert["risk_severity"] = "LOW"
            self.db.save_certificate(target_cert)
            
            self.db.save_audit_log(
                action="CERTIFICATE_RENEWED",
                details=f"Renewed certificate for {common_name}. Old cert marked as replaced.",
                actor="PKI Manager"
            )
            return True
        except Exception as e:
            log.error(f"Certificate renewal failed: {e}")
            return False

    def revoke_certificate(self, cert_id: str) -> bool:
        """Mark a certificate as revoked in the database and audit log it."""
        try:
            certs = self.db.get_all_certificates()
            target_cert = next((c for c in certs if c["id"] == cert_id), None)
            if not target_cert:
                log.error(f"Certificate ID {cert_id} not found in inventory.")
                return False

            target_cert["status"] = "REVOKED"
            target_cert["risk_severity"] = "LOW"
            self.db.save_certificate(target_cert)
            
            self.db.save_audit_log(
                action="CERTIFICATE_REVOKED",
                details=f"Revoked certificate for {target_cert['name']}",
                actor="PKI Manager"
            )
            return True
        except Exception as e:
            log.error(f"Certificate revocation failed: {e}")
            return False

    # --- Expiry Check & Reporting ---
    def get_expiring_certificates_report(self, threshold_days: int = 45) -> List[Dict[str, Any]]:
        """Returns certificates expiring within threshold_days."""
        certs = self.db.get_all_certificates()
        expiring = []
        for c in certs:
            if c["status"] == "ACTIVE" and c["days_remaining"] <= threshold_days:
                # Add recommendation
                c["action_required"] = "RENEW/REPLACE"
                expiring.append(c)
        return expiring

    def generate_expiry_report_pdf(self, file_path: str, threshold_days: int = 45) -> str:
        """
        Generates a professional PDF report detailing expiring certificates
        and their associated risk severities.
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            
            expiring = self.get_expiring_certificates_report(threshold_days)
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Title
            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a2e'),
                spaceAfter=20
            )
            story.append(Paragraph("🛡️ CLM SSL/TLS Certificate Expiry Report", title_style))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
            story.append(Paragraph(f"Lifecycle Expiry Threshold: {threshold_days} Days", styles['Normal']))
            story.append(Spacer(1, 15))

            # Table Header
            table_data = [["Certificate Domain", "Issuer", "Expiry Date", "Days Left", "Risk"]]
            for c in expiring:
                table_data.append([
                    c["name"],
                    c["issuer"],
                    c["expiry_date"][:10],
                    str(c["days_remaining"]),
                    c["risk_severity"]
                ])

            if len(expiring) == 0:
                story.append(Paragraph("✓ Great news! No certificates are expiring within the next 45 days.", styles['Normal']))
            else:
                t = Table(table_data, colWidths=[150, 120, 90, 80, 80])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,0), 8),
                    ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#dee2e6')),
                    # Dynamic risk highlighting
                    ('TEXTCOLOR', (4,1), (4,-1), colors.red),
                ]))
                story.append(t)

            doc.build(story)
            log.info(f"PDF certificate expiry report generated: {file_path}")
            return file_path
        except Exception as e:
            log.error(f"Failed to generate PDF report: {e}")
            return ""
