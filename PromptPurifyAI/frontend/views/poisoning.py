import os
import sys

import streamlit as st

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from promptpurify_integration import detect_poisoning_sync
from components.page_utils import log_scan, show_engine_banner


def render(db=None) -> None:
    st.title("🧪 Model Poisoning Detector")
    st.markdown("Analyze training data snippets or model outputs for contamination and backdoors.")
    show_engine_banner()

    col1, col2 = st.columns(2)
    with col1:
        training_data = st.text_area("Training data snippet (optional)", height=150, key="pp_train")
    with col2:
        model_output = st.text_area("Model output (optional)", height=150, key="pp_output")

    if st.button("Detect poisoning", key="pp_pois_btn"):
        if not (training_data or model_output):
            st.warning("Please provide training data and/or model output.")
            return
        with st.spinner("Analyzing for poisoning..."):
            try:
                result = detect_poisoning_sync(
                    training_snippet=training_data or None,
                    model_output=model_output or None,
                )
                log_scan(
                    db,
                    "PROMPTPURIFY_POISONING_SCAN",
                    f"probability={result.get('probability')} engine={result.get('engine')}",
                )
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                return

        st.subheader("Poisoning analysis")
        pct = int(float(result.get("probability", 0)) * 100)
        st.metric("Poisoning probability", f"{pct}%")
        st.metric("Confidence", f"{int(float(result.get('confidence', 0)) * 100)}%")
        st.caption(f"Engine: {result.get('engine', 'unknown')}")
        components = result.get("affected_components") or []
        if components:
            st.error("Suspected components: " + ", ".join(components))
        elif pct < 30:
            st.success("No significant poisoning detected in the provided samples.")
        else:
            st.warning("Elevated poisoning risk — review samples manually.")
