import os
import sys
import time
import json
import hashlib
import asyncio
import pandas as pd
import binascii
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone


# Simple authentication handling
AUTH_USERNAME = os.getenv('APP_USERNAME', 'admin')
AUTH_PASSWORD = os.getenv('APP_PASSWORD', 'password123')
AUTH_DISABLED = os.getenv('AUTH_DISABLED', 'false').strip().lower() in ('1', 'true', 'yes')

if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
    st.session_state['auth_error'] = ''


def authenticate_user(username: str, password: str) -> bool:
    if AUTH_DISABLED:
        return True
    return username == AUTH_USERNAME and password == AUTH_PASSWORD


if not st.session_state['authenticated']:
    if AUTH_DISABLED:
        st.session_state['authenticated'] = True
    else:
        st.sidebar.title('🔐 User Authentication')
        with st.sidebar.form('login_form'):
            auth_user = st.text_input('Username', value='')
            auth_pass = st.text_input('Password', type='password', value='')
            submitted = st.form_submit_button('Login')
            if submitted:
                if authenticate_user(auth_user, auth_pass):
                    st.session_state['authenticated'] = True
                    st.session_state['auth_error'] = ''
                else:
                    st.session_state['auth_error'] = 'Invalid credentials'
        if st.session_state['auth_error']:
            st.sidebar.error(st.session_state['auth_error'])
        st.sidebar.info(f'Use {AUTH_USERNAME} / {AUTH_PASSWORD} or set APP_USERNAME/APP_PASSWORD in your environment')
        st.stop()

# Import backend modules after authentication check
from backend.database import DatabaseClient
from backend.hsm import EntrustShieldHSMSimulator
from backend.pki import CertificateLifecycleManager
from backend.quantum import QuantumKeyGenerator, QuantumFileEncryptor, ShorSimulator, QuantumThreatAuditor, QuantumSignatureEngine
from backend.agents import PKISecurityCrew
from firewall.scanner import FirewallScanAgent

# Page configuration
st.set_page_config(
    page_title="Venafi-like PKI & CLM Quantum Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))



# Page configuration
st.set_page_config(
    page_title="Venafi-like PKI & CLM Quantum Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Custom CSS Styling (Glassmorphism & Neon accents)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap');
    
    /* Global Styles */
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Sidebar styling */
    .stSidebar {
        background-color: #0d1117 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    /* Metric Cards */
    .metric-card {
        background: rgba(22, 27, 34, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 242, 254, 0.4);
    }
    .metric-title {
        font-size: 0.9rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 800;
        margin: 5px 0;
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-desc {
        font-size: 0.8rem;
        color: #58a6ff;
    }
    
    /* Section Glass Cards */
    .glass-card {
        background: rgba(13, 17, 23, 0.6);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 25px;
        margin-bottom: 25px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
    }
    
    /* Gradient Headers */
    .glow-header {
        background: linear-gradient(135deg, #ff007f 0%, #7f00ff 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }
    
    .glow-header-cyan {
        background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }
    
    /* Custom Alerts */
    .alert-banner {
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 15px;
        font-weight: 500;
    }
    .alert-critical {
        background: rgba(248, 81, 73, 0.15);
        border: 1px solid rgba(248, 81, 73, 0.3);
        color: #ff7b72;
    }
    .alert-warning {
        background: rgba(210, 153, 34, 0.15);
        border: 1px solid rgba(210, 153, 34, 0.3);
        color: #d29922;
    }
    .alert-success {
        background: rgba(56, 139, 253, 0.15);
        border: 1px solid rgba(56, 139, 253, 0.3);
        color: #58a6ff;
    }
    
    /* Code styling */
    code {
        color: #ff7b72 !important;
        background: rgba(110, 118, 129, 0.2) !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 2. Database Connection and Mock Prepopulation
# ─────────────────────────────────────────────────────────────────────────────
# Credentials configuration (sidebar configuration)
st.sidebar.markdown("<h2 class='glow-header-cyan'>⚙️ System Config</h2>", unsafe_allow_html=True)
sb_url = st.sidebar.text_input("Supabase URL", value=os.getenv("SUPABASE_URL", ""), type="default")
sb_key = st.sidebar.text_input("Supabase Key", value=os.getenv("SUPABASE_KEY", ""), type="password")
groq_key = st.sidebar.text_input("Groq API Key", value=os.getenv("GROQ_API_KEY", ""), type="password")

if sb_url and sb_key:
    os.environ["SUPABASE_URL"] = sb_url
    os.environ["SUPABASE_KEY"] = sb_key
if groq_key:
    os.environ["GROQ_API_KEY"] = groq_key

# Initialize DB, HSM, and CLM
@st.cache_resource
def get_system_components():
    db = DatabaseClient()
    hsm = EntrustShieldHSMSimulator(db)
    clm = CertificateLifecycleManager(db, hsm)
    return db, hsm, clm

db, hsm, clm = get_system_components()

# Pre-populate database with samples if empty
def prepopulate_database():
    certs = db.get_all_certificates()
    if not certs:
        log.info("Pre-populating database with mock enterprise data...")
        
        # 1. Healthy Enterprise Certificate (HSM Signed)
        clm.issue_new_certificate("enterprise.intranet", key_size=4096, validity_days=365)
        
        # 2. Expiring External Certificate (Let's Encrypt, High Risk)
        expiring_cert = {
            "name": "billing-portal.extranet.com",
            "issuer": "R3 (Let's Encrypt)",
            "expiry_date": (datetime.now(timezone.utc) + pd.Timedelta(days=8)).isoformat(),
            "days_remaining": 8,
            "risk_severity": "CRITICAL",
            "status": "ACTIVE",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx4q... (RSA-2048)\n-----END PUBLIC KEY-----",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        db.save_certificate(expiring_cert)
        
        # 3. Medium-risk Cert expiring in 35 days
        warning_cert = {
            "name": "internal-dev.corp.net",
            "issuer": "DigiCert SHA2 Secure Server CA",
            "expiry_date": (datetime.now(timezone.utc) + pd.Timedelta(days=35)).isoformat(),
            "days_remaining": 35,
            "risk_severity": "HIGH",
            "status": "ACTIVE",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs0d... (RSA-2048)\n-----END PUBLIC KEY-----",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        db.save_certificate(warning_cert)

        # 4. Insecure legacy certificate (RSA 1024, Critical risk)
        legacy_cert = {
            "name": "legacy-auth.internal",
            "issuer": "Internal Root v1",
            "expiry_date": (datetime.now(timezone.utc) + pd.Timedelta(days=120)).isoformat(),
            "days_remaining": 120,
            "risk_severity": "HIGH", # High due to key length
            "status": "ACTIVE",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHuF... (RSA-1024)\n-----END PUBLIC KEY-----",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        db.save_certificate(legacy_cert)

        # Pre-populate some firewall scans
        scan_data = {
            "target_host": "localhost",
            "ip_address": "127.0.0.1",
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "open_ports": [
                {"port": 443, "protocol": "TCP", "state": "OPEN", "service": "HTTPS", "risk": "ALLOWED", "response_ms": 1.2},
                {"port": 22, "protocol": "TCP", "state": "OPEN", "service": "SSH", "risk": "HIGH", "response_ms": 5.4},
                {"port": 3306, "protocol": "TCP", "state": "OPEN", "service": "MySQL", "risk": "HIGH", "response_ms": 12.1}
            ],
            "blocked_ports": [],
            "is_compliant": False,
            "scan_duration_s": 0.45
        }
        db.save_firewall_scan(scan_data)
        
        # Prepopulate audits
        q_auditor = QuantumThreatAuditor(db)
        q_auditor.audit_certificates()
        
        db.save_audit_log("DATABASE_SEEDING", "Seeded system database with default high-assurance CLM mock data.")

prepopulate_database()

# DB status indicator in sidebar
db_type = "Cloud Supabase" if db.use_supabase else "Local SQLite"
db_color = "#58a6ff" if db.use_supabase else "#8b949e"
st.sidebar.markdown(f"""
<div style='background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px; margin-top: 15px;'>
    <div style='font-size: 0.8rem; color: #8b949e;'>DATABASE STORAGE:</div>
    <div style='font-weight: 600; color: {db_color};'>{db_type}</div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 3. Main Dashboard Layout & Tabs
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("<h1 class='glow-header'>🛡️ Quantum PKI & CLM Shield</h1>", unsafe_allow_html=True)
st.markdown("##### High-Assurance Certificate Lifecycle Management (CLM) & Quantum Threat Intelligence Dashboard")

tabs = st.tabs([
    "📊 Overview", 
    "🔑 Cert Lifecycle", 
    "🧱 Firewall Auditor", 
    "⚛️ Quantum Sandbox", 
    "🤖 Multi-Agent GRC"
])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
with tabs[0]:
    # Update metrics
    certs = db.get_all_certificates()
    scans = db.get_firewall_scans()
    
    total_certs = len(certs)
    expiring_45d = len([c for c in certs if c["days_remaining"] <= 45 and c["status"] == "ACTIVE"])
    revoked_count = len([c for c in certs if c["status"] == "REVOKED"])
    
    open_ports_count = 0
    compliance_status = "Compliant"
    if scans:
        open_ports_count = len(scans[0]["open_ports"])
        compliance_status = "Secure (443 only)" if scans[0]["is_compliant"] else "Non-Compliant"

    hsm_stat = hsm.get_status()

    # Cards layout
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Active Certificates</div>
            <div class="metric-value">{total_certs - revoked_count}</div>
            <div class="metric-desc">HSM Signed Root online</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Critical Expirations (45 Days)</div>
            <div class="metric-value" style="background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">{expiring_45d}</div>
            <div class="metric-desc">Action Required immediately</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Firewall Exposure</div>
            <div class="metric-value" style="background: linear-gradient(135deg, #F953C6 0%, #b91d73 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">{open_ports_count} Open</div>
            <div class="metric-desc">{compliance_status}</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">HSM Cryptoprovider</div>
            <div class="metric-value" style="font-size: 1.6rem; margin-top: 15px; margin-bottom: 12px; background: linear-gradient(135deg, #00B4DB 0%, #0083B0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">FIPS 140-2 L3</div>
            <div class="metric-desc">Temp: {hsm_stat['temperature']} | Sensor: {hsm_stat['sensors']}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Secondary layout
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.markdown("<div class='glass-card'><h4>📋 Certificate Expiry Distribution</h4>", unsafe_allow_html=True)
        if certs:
            df_certs = pd.DataFrame(certs)
            df_certs = df_certs[df_certs["status"] == "ACTIVE"]
            fig = px.bar(
                df_certs, 
                x="name", 
                y="days_remaining", 
                color="risk_severity",
                color_discrete_map={"LOW": "#388bfd", "HIGH": "#d29922", "CRITICAL": "#f85149"},
                labels={"days_remaining": "Days to Expiration", "name": "Certificate CommonName"},
                template="plotly_dark",
                height=300
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=0, t=10, b=0)
            )
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("No active certificates in database.")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown("<div class='glass-card'><h4>🛠️ Active HSM CA Profile</h4>", unsafe_allow_html=True)
        st.markdown(f"""
        - **Model:** `{hsm_stat['model']}`
        - **Firmware Version:** `{hsm_stat['firmware']}`
        - **FIPS Certification:** `{hsm_stat['fips_compliance']}`
        - **Root Cert Expiry:** `{hsm_stat['root_cert_expiry'][:10]}`
        - **Anti-tamper Sensors:** `{hsm_stat['sensors']}`
        """)
        st.markdown("</div>", unsafe_allow_html=True)

    # Audit log panel
    st.markdown("<div class='glass-card'><h4>🛡️ High-Assurance PKI Audit Trail</h4>", unsafe_allow_html=True)
    logs = db.get_audit_logs()
    if logs:
        df_logs = pd.DataFrame(logs)[["timestamp", "action", "details", "actor"]].head(15)
        st.dataframe(
            df_logs,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Timestamp"),
                "action": "Action Group",
                "details": "Security Operations Details",
                "actor": "System Component"
            },
            hide_index=True,
            width='stretch'
        )
    else:
        st.info("No audit logs captured yet.")
    st.markdown("</div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: CERTIFICATE LIFECYCLE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
with tabs[1]:
    st.markdown("<div class='glass-card'><h3>🔑 Enterprise Certificate Lifecycle Operations</h3>", unsafe_allow_html=True)
    
    # Expiry Warners
    expiring_certs = clm.get_expiring_certificates_report(45)
    if expiring_certs:
        for c in expiring_certs:
            st.markdown(f"""
            <div class="alert-banner alert-critical">
                ⚠️ <strong>CRITICAL:</strong> <code>{c['name']}</code> is expiring in <strong>{c['days_remaining']} days</strong> ({c['expiry_date'][:10]}).
                Risk: <strong>{c['risk_severity']}</strong>. Recommend immediate renewal.
            </div>
            """, unsafe_allow_html=True)

    # Cert inventory table
    st.markdown("#### Centralized Certificate Inventory")
    certs = db.get_all_certificates()
    if certs:
        df_inv = pd.DataFrame(certs)
        st.dataframe(
            df_inv[["id", "name", "issuer", "expiry_date", "days_remaining", "risk_severity", "status"]],
            column_config={
                "id": "Cert UUID",
                "name": "Domain / CommonName",
                "issuer": "Signatory CA / Issuer",
                "expiry_date": "Expiration",
                "days_remaining": "Days Left",
                "risk_severity": "Risk",
                "status": "State"
            },
            hide_index=True,
            width='stretch'
        )
    else:
        st.info("No certificates inventoried.")

    col_cl1, col_cl2 = st.columns(2)
    with col_cl1:
        st.markdown("<div style='background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); padding: 20px; border-radius: 12px;'>", unsafe_allow_html=True)
        st.markdown("##### 🔐 Generate HSM-Issued Certificate")
        new_cn = st.text_input("Common Name (e.g. app.secure.corp)", value="api.service.local")
        new_key_size = st.selectbox("RSA Key Size", options=[2048, 4096], index=0)
        new_validity = st.slider("Validity (Days)", min_value=1, max_value=365, value=90)
        
        if st.button("Generate & Sign via HSM"):
            with st.spinner("Generating client key pair and signing CSR inside FIPS HSM..."):
                try:
                    new_cert = clm.issue_new_certificate(new_cn, key_size=new_key_size, validity_days=new_validity)
                    st.success(f"Certificate successfully signed and issued for {new_cn}!")
                    st.rerun()
                except Exception as e:
                    st.error(f"HSM Signing failed: {e}")
        
        # SSL Network Discovery
        st.markdown("<br><h5>🌐 SSL/TLS Certificate Network Discovery Scanner</h5>", unsafe_allow_html=True)
        d_col1, d_col2 = st.columns([3, 1])
        with d_col1:
            discover_host = st.text_input("Enter Target Host IP or Domain", value="google.com")
        with d_col2:
            discover_port = st.number_input("Port", min_value=1, max_value=65535, value=443)
        
        try:
            cert_res = clm.scan_network_target(discover_host, discover_port)
            if cert_res:
                st.markdown(f"""
                <div class=\"alert-banner alert-success\">
                    ✓ Certificate Discovered: <strong>{cert_res['name']}</strong><br>
                    Issuer: {cert_res['issuer']} | Expiry: {cert_res['expiry_date'][:10]} ({cert_res['days_remaining']} days remaining)
                </div>
                """, unsafe_allow_html=True)
                # Store discovered cert info in session for later use
                st.session_state.discovered_cert = cert_res
            else:
                st.error("No certificate data returned. The target may not support TLS or the port is closed.")
        except Exception as e:
            # Detailed debug info for production scans
            st.error(f"Failed to discover SSL/TLS certificate on {discover_host}:{discover_port}. Error: {e}")
            if st.checkbox("Show debug details"):
                st.exception(e)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_cl2:
        st.markdown("<div style='background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); padding: 20px; border-radius: 12px;'>", unsafe_allow_html=True)
        st.markdown("##### 🔄 Certificate Renewal / Revocation")
        cert_options = {c["id"]: f"{c['name']} ({c['status']})" for c in certs if c["status"] == "ACTIVE"}
        
        if cert_options:
            selected_cert_id = st.selectbox("Select Active Certificate", options=list(cert_options.keys()), format_func=lambda x: cert_options[x])
            
            c_col1, c_col2 = st.columns(2)
            with c_col1:
                if st.button("🔄 Auto-Renew via HSM"):
                    if clm.renew_certificate(selected_cert_id):
                        st.success("Certificate successfully renewed!")
                        st.rerun()
            with c_col2:
                if st.button("🚫 Revoke Certificate"):
                    if clm.revoke_certificate(selected_cert_id):
                        st.warning("Certificate marked as REVOKED.")
                        st.rerun()
        else:
            st.info("No active certificates available for renewal or revocation.")
        st.markdown("</div>", unsafe_allow_html=True)



# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: FIREWALL AUDITOR
# ─────────────────────────────────────────────────────────────────────────────
with tabs[2]:
    st.markdown("<div class='glass-card'><h3>🧱 Firewall Auditor & Port Exposure Controller</h3>", unsafe_allow_html=True)
    
    st.markdown("""
    This utility scans network ports to audit firewall compliance. Under <strong>FIPS & PCI-DSS rules</strong>, 
    only HTTPS port 443 is permitted for web servers. Any other open ports are classified as vulnerable and blocked.
    """)

    f_col1, f_col2 = st.columns([3, 1])
    with f_col1:
        scan_target_ip = st.text_input("Port Scan Target Range (Default: localhost)", value="localhost")
        port_range_str = st.text_input("Port Range (1 - 65000)", value="1-1000")
    with f_col2:
        auto_block_toggle = st.checkbox("Enable Auto-Blocking Policy", value=False, help="Automatically block non-443 open ports via system firewall (netsh / iptables)")
        
    if st.button("🛡️ Execute Port Security Audit"):
        try:
            p_start, p_end = map(int, port_range_str.split("-"))
        except Exception:
            p_start, p_end = 1, 1000
            st.warning("Invalid range format. Defaulting to 1-1000.")
            
        with st.spinner("Executing asynchronous connect-scan..."):
            agent = FirewallScanAgent(
                hosts=[scan_target_ip],
                port_range=(p_start, p_end),
                auto_block=auto_block_toggle,
                report_dir="reports"
            )
            
            # Run async scan in loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scan_summary = loop.run_until_complete(agent.run())
            
            # Save to Database
            db.save_firewall_scan({
                "target_host": scan_target_ip,
                "ip_address": scan_summary["targets"][0]["ip"],
                "open_ports": scan_summary["targets"][0]["open"],
                "blocked_ports": scan_summary["targets"][0]["blocked"],
                "is_compliant": scan_summary["targets"][0]["compliant"],
                "scan_duration_s": 0.5 # Dummy
            })
            
            db.save_audit_log(
                "FIREWALL_SCAN_COMPLETED", 
                f"Scanned {scan_target_ip} ({p_start}-{p_end}). Found {len(scan_summary['targets'][0]['open'])} open ports. Compliance: {scan_summary['targets'][0]['compliant']}"
            )
            
            st.success("Firewall port scan completed successfully!")
            st.rerun()

    # Display last scan findings
    if scans:
        last_scan = scans[0]
        st.markdown(f"#### Last Scan Report: `{last_scan['target_host']}` ({last_scan['scan_time'][:16].replace('T', ' ')})")
        
        compliance_badge = "<span class='badge bg-success'>✓ COMPLIANT</span>" if last_scan["is_compliant"] else "<span class='badge bg-danger'>✗ NON-COMPLIANT</span>"
        st.markdown(f"**Compliance Status:** {compliance_badge}", unsafe_allow_html=True)
        st.markdown(f"**Scan Duration:** `{last_scan.get('scan_duration_s', 0.0)}s` | **IP Address:** `{last_scan['ip_address']}`")
        
        if last_scan["open_ports"]:
            st.markdown("##### Port Findings Detail")
            port_rows = []
            for p in last_scan["open_ports"]:
                # If parsed as direct integers (e.g. from DB) or dict
                if isinstance(p, dict):
                    port_num = p.get("port")
                    state = p.get("state")
                    service = p.get("service")
                    risk = p.get("risk")
                else:
                    # Integer from list
                    port_num = p
                    state = "OPEN"
                    from firewall.scanner import WELL_KNOWN_PORTS, PORT_RISK
                    service = WELL_KNOWN_PORTS.get(port_num, "Unknown")
                    risk = PORT_RISK.get(port_num, "HIGH") if port_num != 443 else "ALLOWED"
                
                # Check if this port is blocked
                is_blocked = port_num in last_scan.get("blocked_ports", [])
                status_str = "BLOCKED ✓" if is_blocked else state

                port_rows.append({
                    "Port": port_num,
                    "Protocol": "TCP",
                    "State": status_str,
                    "Service": service,
                    "Risk Level": risk
                })
            
            st.table(pd.DataFrame(port_rows))
        else:
            st.markdown("""
            <div class="alert-banner alert-success">
                ✓ <strong>All clear!</strong> No open network ports detected. System interface is dark.
            </div>
            """, unsafe_allow_html=True)
            
        # Download reports
        reports_dir = "reports"
        if os.path.exists(reports_dir):
            files = [f for f in os.listdir(reports_dir) if os.path.isfile(os.path.join(reports_dir, f))]
            html_files = sorted([f for f in files if f.endswith(".html")], reverse=True)
            csv_files = sorted([f for f in files if f.endswith(".csv")], reverse=True)
            
            if html_files:
                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    with open(os.path.join(reports_dir, html_files[0]), "r", encoding="utf-8") as f:
                        st.download_button("Download Latest HTML Report", data=f.read(), file_name=html_files[0], mime="text/html")
                with col_d2:
                    with open(os.path.join(reports_dir, csv_files[0]), "r") as f:
                        st.download_button("Download Latest CSV Report", data=f.read(), file_name=csv_files[0], mime="text/csv")
    else:
        st.info("No firewall scan records found in the database. Execute a port scan above to start.")
    st.markdown("</div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4: QUANTUM SANDBOX
# ─────────────────────────────────────────────────────────────────────────────
with tabs[3]:
    st.markdown("<div class='glass-card'><h3>⚛️ Shor's Algorithm & Post-Quantum Cryptography Sandbox</h3>", unsafe_allow_html=True)
    
    st.markdown("""
    This tab evaluates the threat quantum computing poses to our active certificate keys using **Shor's Integer Factorization algorithm**, 
    and offers a **Quantum-Random Key (QRNG)** vault to secure your local files.
    """)

    sub_tab1, sub_tab2, sub_tab3 = st.tabs(["🚀 Shor's Factorization Visualizer", "🔒 Quantum-Secured File Vault", "✍️ Quantum-Safe Digital Signatures"])
    
    # Shor Visualizer
    with sub_tab1:
        st.markdown("#### Shor's Algorithm Factorization (N=15, a=7)")
        st.write("Shor's algorithm can factor integers in polynomial time $O((\\log N)^3)$ on a quantum computer, threatening RSA certificates.")
        
        if st.button("Run Shor's Quantum Period-Finding Simulator"):
            with st.spinner("Initializing qubits, establishing Hadamard superposition, running controlled modular multipliers, and performing Inverse QFT..."):
                shor = ShorSimulator()
                result = shor.run_shor_15()
                
                # Show steps
                for step in result["steps"]:
                    st.markdown(f"##### Step {step['step']}: {step['title']}")
                    st.write(step["description"])
                    
                    if "data" in step:
                        # Draw bar chart of measurement results
                        counts = step["data"]
                        fig = px.bar(
                            x=list(counts.keys()), 
                            y=list(counts.values()),
                            labels={"x": "Measured Control Register State", "y": "Shot Count (Frequency)"},
                            title="Control Register Measurement Probabilities",
                            template="plotly_dark",
                            height=250
                        )
                        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                        width='stretch'
                    
                    if "circuit" in step:
                        st.code(step["circuit"])
                        
                st.success(f"Success! Shor's Algorithm factored N=15 into: **{result['factors'][0]}** and **{result['factors'][1]}**")
                db.save_audit_log("SHOR_SIMULATION", "Executed Shor's Algorithm period-finding simulator for RSA modulus factoring.")

    # File Vault
    with sub_tab2:
        st.markdown("#### Quantum File Encryptor & Decryptor")
        st.write("Generate a symmetric key using a **Qiskit quantum superposition circuit** and encrypt files using AES-256-GCM.")
        
        # Generator
        qrng = QuantumKeyGenerator()
        
        vault_action = st.radio("Select Vault Operation", options=["Encrypt File", "Decrypt File"])
        
        if vault_action == "Encrypt File":
            uploaded_file = st.file_uploader("Upload File to Encrypt", type=["txt", "pdf", "png", "jpg", "zip"])
            if uploaded_file:
                file_bytes = uploaded_file.read()
                
                if st.button("🔐 Encrypt File via Qiskit QRNG"):
                    with st.spinner("Compiling Qiskit quantum circuit, measuring states to extract random bits..."):
                        key, audit = qrng.generate_256_bit_key()
                        encrypted = QuantumFileEncryptor.encrypt_data(file_bytes, key)
                        
                        st.markdown(f"""
                        <div class="alert-banner alert-success">
                            ✓ Key generated via <strong>{audit['source']}</strong>.<br>
                            Symmetric AES Key (hex): <code>{binascii.hexlify(key).decode()}</code><br>
                            <em>Save this key! You will need it to decrypt the file.</em>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Download buttons
                        st.download_button(
                            label="Download Encrypted File (.enc)",
                            data=encrypted,
                            file_name=f"{uploaded_file.name}.enc",
                            mime="application/octet-stream"
                        )
                        db.save_audit_log(
                            "QUANTUM_ENCRYPTION_EXECUTED", 
                            f"Encrypted file {uploaded_file.name} using a 256-bit QRNG key generated via {audit['source']}"
                        )
                        
        else: # Decrypt file
            uploaded_enc_file = st.file_uploader("Upload Encrypted File (.enc)", type=["enc"])
            key_hex = st.text_input("Enter 64-character Hexadecimal AES Key", placeholder="e.g. a5f2b8...", type="password")
            
            if uploaded_enc_file and key_hex:
                if st.button("🔓 Decrypt File"):
                    try:
                        key = binascii.unhexlify(key_hex)
                        enc_bytes = uploaded_enc_file.read()
                        
                        decrypted = QuantumFileEncryptor.decrypt_data(enc_bytes, key)
                        
                        # Deduce original name
                        orig_name = uploaded_enc_file.name.replace(".enc", "")
                        st.success("File decrypted successfully!")
                        
                        st.download_button(
                            label="Download Decrypted File",
                            data=decrypted,
                            file_name=orig_name,
                            mime="application/octet-stream"
                        )
                        db.save_audit_log("QUANTUM_DECRYPTION_EXECUTED", f"Decrypted file {uploaded_enc_file.name} using provided key.")
                    except Exception as e:
                        st.error(f"Decryption failed. Ensure the key is correct. Error: {e}")



        sig_engine = QuantumSignatureEngine()
        qds_action = st.radio("Select Signature Operation", options=["1. Generate Key Pair", "2. Sign Metadata", "3. Verify & Fraud Analyzer"])

        if qds_action == "1. Generate Key Pair":
            st.markdown("##### Generate Post-Quantum Signature Keypair")
            if st.button("Generate QDS Keys"):
                with st.spinner("Harvesting qubits to generate 256-bit hash keypair matrices..."):
                    priv, pub = sig_engine.generate_key_pair()
                    st.success("Quantum keypair matrices successfully generated!")
                    
                    col_k1, col_k2 = st.columns(2)
                    with col_k1:
                        st.download_button(
                            label="📥 Download QDS Private Key (.json)",
                            data=json.dumps(priv, indent=2),
                            file_name="qds_private_key.json",
                            mime="application/json"
                        )
                    with col_k2:
                        st.download_button(
                            label="📥 Download QDS Public Key (.json)",
                            data=json.dumps(pub, indent=2),
                            file_name="qds_public_key.json",
                            mime="application/json"
                        )

        elif qds_action == "2. Sign Metadata":
            st.markdown("##### Create Secure Quantum Signature")
            signer_name = st.text_input("Signer Common Name / Email", value="alice@enterprise.intranet")
            signer_role = st.text_input("Signer Professional Role / Department", value="CISO (Security Operations)")
            doc_content = st.text_area("Document Content / Metadata payload to verify", value="Approve Root CA transition to ML-DSA quantum algorithm.")
            
            uploaded_priv = st.file_uploader("Upload QDS Private Key File (.json)", type=["json"])
            
            if uploaded_priv and st.button("✍️ Sign Metadata Bundle"):
                try:
                    priv_key_bundle = json.loads(uploaded_priv.read().decode())
                    if "keys" not in priv_key_bundle:
                        st.error("Invalid key format. Missing private secret key matrix.")
                    else:
                        combined_msg = f"Signer:{signer_name}|Role:{signer_role}|Payload:{doc_content}"
                        signature = sig_engine.sign_message(combined_msg, priv_key_bundle)
                        
                        # Derive public key matrix from private keys to bundle it for verification
                        derived_pub = []
                        for pair in priv_key_bundle["keys"]:
                            pub0 = hashlib.sha256(bytes.fromhex(pair[0])).hexdigest()
                            pub1 = hashlib.sha256(bytes.fromhex(pair[1])).hexdigest()
                            derived_pub.append([pub0, pub1])
                            
                        signature_bundle = {
                            "signer_name": signer_name,
                            "signer_role": signer_role,
                            "document_payload": doc_content,
                            "signature": signature,
                            "public_key_matrix": derived_pub
                        }
                        
                        st.success("Metadata payload successfully signed using Quantum-Safe scheme!")
                        st.download_button(
                            label="📥 Download Signed Signature Bundle (.json)",
                            data=json.dumps(signature_bundle, indent=2),
                            file_name="signature_bundle.json",
                            mime="application/json"
                        )
                except Exception as e:
                    st.error(f"Failed to generate signature: {e}")

        elif qds_action == "3. Verify & Fraud Analyzer":
            st.markdown("##### Post-Quantum Fraud Analyzer & Tampering Verification")
            st.write("Upload a signature bundle. The verifier will match the signature against the document metadata. You can edit the text below to simulate a tampered document (fraud).")
            
            uploaded_bundle = st.file_uploader("Upload Signature Bundle File (.json)", type=["json"])
            
            if uploaded_bundle:
                try:
                    bundle = json.loads(uploaded_bundle.read().decode())
                    
                    st.markdown("###### Signature Metadata:")
                    col_b1, col_b2 = st.columns(2)
                    with col_b1:
                        st.info(f"👤 **Signer CN:** `{bundle.get('signer_name')}`")
                    with col_b2:
                        st.info(f"💼 **Role:** `{bundle.get('signer_role')}`")
                        
                    # Edit payload sandbox
                    tamper_payload = st.text_area("Edit payload to simulate fraud / verify live integrity:", value=bundle.get("document_payload", ""))
                    
                    combined_msg = f"Signer:{bundle.get('signer_name')}|Role:{bundle.get('signer_role')}|Payload:{tamper_payload}"
                    
                    signature = bundle.get("signature", [])
                    pub_keys = bundle.get("public_key_matrix", [])
                    
                    if not signature or not pub_keys:
                        st.error("Invalid signature bundle format. Missing signature vectors.")
                    else:
                        pub_bundle = {"keys": pub_keys}
                        verify_res = sig_engine.verify_signature(combined_msg, signature, pub_bundle)
                        
                        if verify_res["status"] == "AUTHORIZED":
                            st.markdown(f"""
                            <div class="alert-banner alert-success" style="font-size: 1.1rem; padding: 20px;">
                                🛡️ <strong>VERIFICATION STATUS: ✓ AUTHORIZED SENDER</strong><br>
                                The message integrity and cryptographic signature matches the public key perfectly. No tampering detected.
                            </div>
                            """, unsafe_allow_html=True)
                            db.save_audit_log(
                                "QDS_VERIFICATION_SUCCESSFUL",
                                f"Post-quantum signature verified successfully for signer {bundle.get('signer_name')}."
                            )
                        else:
                            st.markdown(f"""
                            <div class="alert-banner alert-critical" style="font-size: 1.1rem; padding: 20px;">
                                🚨 <strong>VERIFICATION STATUS: ❌ FRAUD DETECTED</strong><br>
                                {verify_res['details']}<br>
                                <em>Alert raised to CLM Security Operations. Mismatched payload.</em>
                            </div>
                            """, unsafe_allow_html=True)
                            db.save_audit_log(
                                "QDS_VERIFICATION_FRAUD_DETECTED",
                                f"FRAUD ALERT: tampered QDS signature for signer {bundle.get('signer_name')}."
                            )
                except Exception as e:
                    st.error(f"Verification failed: {e}")
                        
    # Quantum Threat Audit summary
    st.markdown("<br><h5>🛡️ Post-Quantum Cryptographic (PQC) Certificate Vulnerability Scan</h5>", unsafe_allow_html=True)
    auditor = QuantumThreatAuditor(db)
    
    if st.button("Run PQC Quantum Risk Audit"):
        with st.spinner("Analyzing public key fields..."):
            audits, summary = auditor.audit_certificates()
            st.success("Post-Quantum Audit complete!")
            st.rerun()

    # Quantum Threat Audit results
    q_audits = db.get_quantum_audits()
    if q_audits:
        df_qa = pd.DataFrame(q_audits)
        # Ensure required columns exist
        required_cols = ["cert_name", "key_type", "key_size", "quantum_risk_score", "estimated_break_time_years", "recommended_algorithm"]
        for col in required_cols:
            if col not in df_qa.columns:
                df_qa[col] = None
        # Display the audit table
        st.dataframe(
            df_qa[required_cols],
            column_config={
                "cert_name": "Domain",
                "key_type": "Algorithm",
                "key_size": "Key bits",
                "quantum_risk_score": st.column_config.ProgressColumn("Quantum Risk Score", min_value=0, max_value=100, format="%d%%"),
                "estimated_break_time_years": "Estimated Break Window",
                "recommended_algorithm": "PQC Replacement Candidate"
            },
            hide_index=True,
            width='stretch'
        )
    else:
        st.info("No quantum audits found. Run the PQC vulnerability scan above.")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 5: MULTI-AGENT COMPLIANCE & GRC
# ─────────────────────────────────────────────────────────────────────────────
with tabs[4]:
    st.markdown("<div class='glass-card'><h3>🤖 CrewAI Multi-Agent GRC Compliance Orchestrator</h3>", unsafe_allow_html=True)
    
    st.markdown("""
    Orchestrate a team of AI agents powered by **Groq Llama 3** to audit the certificate lifecycle 
    and network exposures against regulatory frameworks like <strong>PCI-DSS, HIPAA, and ISO 27001</strong>.
    """)

    if not groq_key:
        st.markdown("""
        <div class="alert-banner alert-warning">
            ℹ️ <strong>System Note:</strong> No active Groq API Key was found in the configuration. 
            The system will execute the Multi-Agent audit using <strong>Local Agentic Simulation Mode</strong>. 
            To run a live LLM execution, paste your Groq key into the sidebar configuration.
        </div>
        """, unsafe_allow_html=True)

    if st.button("🚀 Run CrewAI Agentic Audit"):
        with st.spinner("Assembling agent crew: Certificate Officer, Network Auditor, Quantum Analyst, Compliance Officer..."):
            crew = PKISecurityCrew(db, groq_api_key=groq_key)
            result = crew.run_security_audit()
            
            # Store in session state to persist
            st.session_state["crew_audit_result"] = result
            st.success("CrewAI Agent audit completed!")
            st.rerun()

    if "crew_audit_result" in st.session_state:
        res = st.session_state["crew_audit_result"]
        
        st.markdown(f"**Audit Engine:** `{res['engine']}` | **Completed:** `{res['timestamp'][:16].replace('T', ' ')}`")
        
        col_c1, col_c2 = st.columns([1, 1])
        
        with col_c1:
            st.markdown("#### 💬 Agent Collaborative Discussion")
            for msg in res["agent_dialogue"]:
                st.markdown(f"""
                <div style="background: rgba(255,255,255,0.03); border-left: 4px solid #00f2fe; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
                    <div style="font-weight: 700; margin-bottom: 5px;">{msg['avatar']} {msg['agent']}</div>
                    <div style="font-size: 0.9rem; color: #c9d1d9;">{msg['message']}</div>
                </div>
                """, unsafe_allow_html=True)
                
        with col_c2:
            st.markdown("#### 📄 Compiled GRC Audit Report")
            st.markdown(res["report"])
    else:
        st.info("Click 'Run CrewAI Agentic Audit' to assemble the AI agents and analyze compliance.")
    st.markdown("</div>", unsafe_allow_html=True)
