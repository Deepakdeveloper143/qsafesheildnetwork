import os
import sys

import streamlit as st

_FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _FRONTEND_DIR not in sys.path:
    sys.path.insert(0, _FRONTEND_DIR)

from components.auth import check_authentication
from components.utils import load_css
from views import dashboard, multi_agent, owasp, poisoning, scan_prompt

st.set_page_config(
    page_title="PromptPurify AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

load_css()

if not check_authentication():
    st.stop()

st.title("🛡️ PromptPurify AI")
st.markdown("### Advanced AI Security Platform")
st.markdown(
    "Select a module below or use the sidebar when running as a multipage app."
)

tab_dash, tab_scan, tab_pois, tab_owasp, tab_multi = st.tabs([
    "📊 Dashboard",
    "🔍 Scan Prompt",
    "🧪 Poisoning",
    "📋 OWASP LLM Top 10",
    "🤖 Multi-Agent",
])

with tab_dash:
    dashboard.render()
with tab_scan:
    scan_prompt.render()
with tab_pois:
    poisoning.render()
with tab_owasp:
    owasp.render()
with tab_multi:
    multi_agent.render()
