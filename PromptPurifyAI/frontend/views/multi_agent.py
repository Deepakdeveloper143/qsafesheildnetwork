import os
import sys

import streamlit as st

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from promptpurify_integration import multi_agent_scan_sync
from components.page_utils import log_scan, show_engine_banner


def render(db=None) -> None:
    st.title("🤖 Multi-Agent Security Scan")
    st.markdown("Run injection, poisoning, and OWASP analyzers concurrently on one prompt.")
    show_engine_banner()

    multi_prompt = st.text_area("Prompt / context for full scan", height=120, key="pp_multi_prompt")

    if st.button("Run multi-agent scan", key="pp_multi_btn"):
        if not multi_prompt.strip():
            st.warning("Please enter text to analyze.")
            return
        with st.spinner("Running concurrent security agents..."):
            try:
                result = multi_agent_scan_sync(multi_prompt)
                log_scan(
                    db,
                    "PROMPTPURIFY_MULTI_AGENT",
                    f"aggregated_score={result.get('aggregated_score')} engine={result.get('engine')}",
                )
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                return

        st.metric("Aggregated security score", f"{result.get('aggregated_score', 0)}/100")
        st.caption(f"Engine: {result.get('engine', 'unknown')}")
        for agent in result.get("agents", []):
            with st.expander(
                f"{agent.get('agent_name', 'Agent')} (confidence {agent.get('confidence', 0):.0%})"
            ):
                st.json(agent.get("findings", {}))
