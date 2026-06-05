import os
import sys
from typing import Any, Optional

import streamlit as st

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from promptpurify_integration import groq_available  # noqa: E402


def log_scan(db: Any, action: str, details: str) -> None:
    if db is not None and hasattr(db, "save_audit_log"):
        db.save_audit_log(action, details, actor="PromptPurify")


def show_engine_banner() -> None:
    if groq_available():
        st.success("Groq API key detected — live LLM analysis enabled.")
    else:
        st.markdown(
            """
            <div class="alert-banner alert-warning">
                ℹ️ No Groq API key configured. Running in <strong>heuristic mode</strong>.
                Set <code>GROQ_API_KEY</code> in the sidebar or environment for full LLM analysis.
            </div>
            """,
            unsafe_allow_html=True,
        )
