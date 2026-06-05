import os
import sys

import streamlit as st

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from promptpurify_integration import analyze_owasp_sync, format_owasp_chart_data
from components.plotly_charts import create_owasp_bar_chart
from components.page_utils import log_scan, show_engine_banner


def render(db=None) -> None:
    st.title("📋 OWASP LLM Top 10 Analyzer")
    st.markdown("Scan your application context against industry-standard vulnerabilities.")
    show_engine_banner()

    context_input = st.text_area("Application context / prompt", height=150, key="pp_owasp_ctx")

    if st.button("Run OWASP scan", key="pp_owasp_btn"):
        if not context_input.strip():
            st.warning("Please provide context to scan.")
            return
        with st.spinner("Running OWASP compliance checks..."):
            try:
                result = analyze_owasp_sync(context_input)
                log_scan(
                    db,
                    "PROMPTPURIFY_OWASP_SCAN",
                    f"overall_score={result.get('overall_score')} engine={result.get('engine')}",
                )
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                return

        chart_data = format_owasp_chart_data(result.get("compliance_json", {}))
        st.plotly_chart(create_owasp_bar_chart(chart_data), use_container_width=True)
        st.metric("Overall compliance score", f"{result.get('overall_score', 0)}/100")
        st.caption(f"Engine: {result.get('engine', 'unknown')}")
        st.subheader("Detailed breakdown")
        for cat, data in chart_data.items():
            if data.get("passed"):
                st.success(f"**{cat}**: Passed — {data.get('details', '')}")
            else:
                st.error(f"**{cat}**: Failed — {data.get('details', '')}")
