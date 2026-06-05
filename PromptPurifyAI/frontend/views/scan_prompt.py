import os
import sys

import streamlit as st

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from promptpurify_integration import scan_prompt_sync
from components.plotly_charts import create_risk_gauge
from components.page_utils import log_scan, show_engine_banner


def render(db=None) -> None:
    st.title("🔍 Prompt Injection Scanner")
    st.markdown("Analyze prompts for jailbreaks, prompt injection, and manipulation attempts.")
    show_engine_banner()

    prompt_input = st.text_area("Enter prompt for analysis", height=150, key="pp_injection_prompt")

    if st.button("Scan prompt", key="pp_scan_btn"):
        if not prompt_input.strip():
            st.warning("Please enter a prompt to scan.")
            return
        with st.spinner("Analyzing prompt..."):
            try:
                result = scan_prompt_sync(prompt_input)
                log_scan(
                    db,
                    "PROMPTPURIFY_INJECTION_SCAN",
                    f"severity={result.get('severity')} score={result.get('risk_score')} engine={result.get('engine')}",
                )
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                return

        col1, col2 = st.columns([1, 2])
        with col1:
            st.plotly_chart(create_risk_gauge(int(result["risk_score"])), use_container_width=True)
        with col2:
            st.subheader("Analysis results")
            st.caption(f"Engine: {result.get('engine', 'unknown')}")
            st.write(f"**Severity:** {result.get('severity', 'Low')}")
            findings = result.get("findings") or []
            if findings:
                st.write("**Findings:**")
                for finding in findings:
                    st.warning(f"- {finding.get('pattern', 'Pattern')}: {finding.get('description', '')}")
            else:
                st.success("No malicious patterns detected.")
