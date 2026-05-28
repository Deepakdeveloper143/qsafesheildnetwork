import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from backend.database import DatabaseClient

log = logging.getLogger("venafi.hsm")

class EntrustShieldHSMSimulator:
    """
    Simulates a Hardware Security Module (Entrust Shield HSM) in FIPS 140-2 Level 3 mode.
    Guarantees that CA root private keys are never exposed in plaintext outside the simulator.
    """
    def __init__(self, db_client: DatabaseClient):
        self.db = db_client
        self.firmware_version = "v12.80.2"
        self.model = "Entrust Shield HSM Solo XC"
        self.fips_status = "FIPS 140-2 Level 3 Compliant"
        self.tamper_sensors = "OK"
        self.temperature = "34.5 C"
        self.root_private_key = None
        self.root_public_key = None
        self.root_certificate = None
        
        # Load or generate HSM root key
        self._load_or_generate_hsm_state()

    def _load_or_generate_hsm_state(self):
        """Mock persistence of the HSM internal state."""
        hsm_dir = os.path.join("artifacts", "hsm_secure_storage")
        os.makedirs(hsm_dir, exist_ok=True)
        
        private_key_path = os.path.join(hsm_dir, "hsm_root.key")
        cert_path = os.path.join(hsm_dir, "hsm_root.crt")

        if os.path.exists(private_key_path) and os.path.exists(cert_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.root_private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=b"EntrustShield_FIPS_Passphrase_123!", # HSM encryption key wrapper
                        backend=default_backend()
                    )
                with open(cert_path, "rb") as f:
                    self.root_certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
                self.root_public_key = self.root_private_key.public_key()
                log.info("HSM initialized and Root CA keys loaded successfully from secure slot.")
                return
            except Exception as e:
                log.error(f"Failed to load HSM state: {e}. Reinitializing root...")

        # Generate a new root key pair inside the simulated HSM secure storage
        log.warning("Generating new high-assurance Root CA key pair inside HSM...")
        self.root_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.root_public_key = self.root_private_key.public_key()

        # Self-sign the root certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "HSM Root Authority (FIPS 140-2 Level 3)"),
        ])
        
        now = datetime.now(timezone.utc)
        self.root_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.root_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=3650) # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.root_private_key, hashes.SHA256(), default_backend())

        # Save to simulated physical memory (encrypted PEM)
        try:
            pem_key = self.root_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"EntrustShield_FIPS_Passphrase_123!")
            )
            pem_cert = self.root_certificate.public_bytes(serialization.Encoding.PEM)

            with open(private_key_path, "wb") as f:
                f.write(pem_key)
            with open(cert_path, "wb") as f:
                f.write(pem_cert)
                
            self.db.save_audit_log(
                action="HSM_ROOT_KEY_GENERATION",
                details=f"Generated new RSA-4096 Root CA key inside HSM Slot 1. Model: {self.model}",
                actor="Entrust HSM"
            )
            log.info("Successfully generated and saved new HSM Root CA state.")
        except Exception as e:
            log.error(f"Failed to write HSM secure storage: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Return the physical and cryptographic status of the HSM."""
        return {
            "model": self.model,
            "firmware": self.firmware_version,
            "fips_compliance": self.fips_status,
            "sensors": self.tamper_sensors,
            "temperature": self.temperature,
            "root_key_type": "RSA-4096",
            "root_cert_expiry": self.root_certificate.not_valid_after_utc.isoformat() if self.root_certificate else "N/A"
        }

    def sign_csr(self, csr_pem: bytes, expiry_days: int = 365) -> Tuple[bytes, bytes]:
        """
        Sign a client-submitted CSR using the Root private key inside the HSM.
        Returns (issued_cert_pem, root_cert_pem).
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())
            if not csr.is_signature_valid:
                raise ValueError("CSR signature is invalid!")
            
            # HSM policy enforcement: Reject weak key sizes
            pub_key = csr.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                if pub_key.key_size < 2048:
                    raise ValueError("FIPS Policy: Rejecting CSR with RSA key size < 2048 bits.")
            
            # Generate the signed certificate
            now = datetime.now(timezone.utc)
            cert_builder = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                self.root_certificate.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now
            ).not_valid_after(
                now + timedelta(days=expiry_days)
            )

            # Copy requested extensions if present
            for ext in csr.extensions:
                cert_builder = cert_builder.add_extension(ext.value, ext.critical)

            cert = cert_builder.sign(
                self.root_private_key,
                hashes.SHA256(),
                default_backend()
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            root_pem = self.root_certificate.public_bytes(serialization.Encoding.PEM)

            # Audit logging
            subject_cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            self.db.save_audit_log(
                action="HSM_SIGN_CERTIFICATE",
                details=f"Signed CSR for CommonName: {subject_cn} (Validity: {expiry_days} days). Used RSA-4096 Root Key.",
                actor="Entrust HSM"
            )
            return cert_pem, root_pem

        except Exception as e:
            self.db.save_audit_log(
                action="HSM_SIGNING_FAILURE",
                details=f"Failed to sign CSR: {str(e)}",
                actor="Entrust HSM"
            )
            log.error(f"HSM signing error: {e}")
            raise e

    def generate_client_keys_and_csr(self, common_name: str, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Helper to simulate key pair generation and CSR creation on a client machine.
        (Since clients usually send CSRs, this simulates a secure client utility).
        """
        # Client generates private key
        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Build CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Node"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).sign(client_private_key, hashes.SHA256(), default_backend())

        client_key_pem = client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        return client_key_pem, csr_pem
