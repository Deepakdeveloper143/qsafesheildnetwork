import os
import sys
import asyncio
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("venafi.verify")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.database import DatabaseClient
from backend.hsm import EntrustShieldHSMSimulator
from backend.pki import CertificateLifecycleManager
from backend.quantum import QuantumKeyGenerator, QuantumFileEncryptor, ShorSimulator, QuantumThreatAuditor, QuantumSignatureEngine
from firewall.scanner import FirewallScanAgent

def test_database_and_hsm():
    log.info("--- Testing Database & HSM Simulator ---")
    db = DatabaseClient()
    hsm = EntrustShieldHSMSimulator(db)
    
    status = hsm.get_status()
    log.info(f"HSM Status: {status}")
    assert status["model"] == "Entrust Shield HSM Solo XC"
    
    # Test logging
    db.save_audit_log("VERIFICATION_TEST", "Verified database and HSM interface.")
    log.info("Database and HSM initialization test: PASSED")
    return db, hsm

def test_pki_lifecycle(db, hsm):
    log.info("--- Testing PKI Certificate Lifecycle ---")
    clm = CertificateLifecycleManager(db, hsm)
    
    # Test cert generation
    common_name = "test-verification.local"
    cert = clm.issue_new_certificate(common_name, key_size=2048, validity_days=30)
    log.info(f"Issued certificate details: {cert}")
    assert cert["name"] == common_name
    assert cert["days_remaining"] <= 30
    assert cert["risk_severity"] in ["HIGH", "CRITICAL", "LOW"]
    
    # Test expiry report
    expiring = clm.get_expiring_certificates_report(45)
    log.info(f"Expiring Certificates (<45 days): {len(expiring)}")
    assert len(expiring) > 0  # Our test cert is expiring in 30 days
    
    # Test renewal
    certs = db.get_all_certificates()
    target_cert = next(c for c in certs if c["name"] == common_name and c["status"] == "ACTIVE")
    success = clm.renew_certificate(target_cert["id"])
    log.info(f"Certificate renewal status: {success}")
    assert success is True
    
    log.info("PKI Lifecycle Management test: PASSED")
    return clm

def test_quantum_cryptography(db):
    log.info("--- Testing Quantum Cryptography & Shor's Algorithm ---")
    
    # Test Key generator
    qrng = QuantumKeyGenerator()
    key, audit = qrng.generate_256_bit_key()
    log.info(f"QRNG Key Generated: {key.hex()[:20]}... via {audit['source']}")
    assert len(key) == 32
    
    # Test Encrypt / Decrypt
    plaintext = b"Venafi Quantum Shield Verification Payload"
    encrypted = QuantumFileEncryptor.encrypt_data(plaintext, key)
    decrypted = QuantumFileEncryptor.decrypt_data(encrypted, key)
    log.info(f"Decrypted text: {decrypted.decode()}")
    assert decrypted == plaintext
    
    # Test Shor Factorizer
    shor = ShorSimulator()
    res = shor.run_shor_15()
    log.info(f"Shor factors of 15: {res['factors']}")
    assert res["factors"] == (3, 5) or res["factors"] == (5, 3)

    # Test PQC Auditor
    auditor = QuantumThreatAuditor(db)
    audits, summary = auditor.audit_certificates()
    log.info(f"PQC Audit summary: {summary}")
    assert summary["total_audited"] > 0
    
    # Test Quantum Digital Signature Engine
    log.info("Testing Quantum Digital Signature Engine...")
    sig_engine = QuantumSignatureEngine()
    priv_key, pub_key = sig_engine.generate_key_pair()
    assert "keys" in priv_key and "keys" in pub_key
    
    test_msg = "Signer:alice@enterprise.intranet|Role:CISO|Payload:Approved"
    signature = sig_engine.sign_message(test_msg, priv_key)
    assert len(signature) == 256
    
    # Verify valid signature
    verify_ok = sig_engine.verify_signature(test_msg, signature, pub_key)
    log.info(f"Valid Signature verification result: {verify_ok}")
    assert verify_ok["status"] == "AUTHORIZED"
    
    # Verify tampered message (fraud detection)
    tampered_msg = "Signer:alice@enterprise.intranet|Role:CISO|Payload:REJECTED"
    verify_fail = sig_engine.verify_signature(tampered_msg, signature, pub_key)
    log.info(f"Tampered message verification result (expected fraud): {verify_fail}")
    assert verify_fail["status"] == "FRAUD"
    
    log.info("Quantum Cryptography and Shor's simulation test: PASSED")

def test_firewall_scanner():
    log.info("--- Testing Firewall Scanner & Policy Enforcer ---")
    
    # Run a simple scan on localhost for port 80 and 443
    agent = FirewallScanAgent(
        hosts=["127.0.0.1"],
        port_range=(80, 80),
        extra_ports=[443],
        auto_block=False,
        report_dir="reports"
    )
    
    loop = asyncio.get_event_loop()
    summary = loop.run_until_complete(agent.run())
    log.info(f"Firewall Scan Summary: {summary}")
    assert summary["hosts_scanned"] == 1
    
    log.info("Firewall scan and reporting test: PASSED")

def main():
    log.info("Starting System-Wide Verification Sequence...")
    try:
        db, hsm = test_database_and_hsm()
        clm = test_pki_lifecycle(db, hsm)
        test_quantum_cryptography(db)
        test_firewall_scanner()
        log.info("=== ALL SYSTEM VERIFICATION TESTS PASSED SUCCESSFULLY! ===")
    except Exception as e:
        log.error(f"Verification test FAILED: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
