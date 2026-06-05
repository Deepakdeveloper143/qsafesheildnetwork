import streamlit as st
import pandas as pd
import plotly.express as px


def render(db=None) -> None:
    st.title("📊 Security Dashboard")
    st.markdown("Overview of your platform's security posture.")

    audit_rows = []
    if db is not None and hasattr(db, "get_audit_logs"):
        try:
            logs = db.get_audit_logs()[:50]
            for row in logs:
                action = str(row.get("action", ""))
                if "PROMPTPURIFY" in action.upper():
                    audit_rows.append({
                        "Timestamp": row.get("timestamp", ""),
                        "Action": action.replace("PROMPTPURIFY_", "").replace("_", " ").title(),
                        "Details": row.get("details", ""),
                        "Actor": row.get("actor", ""),
                    })
        except Exception:
            audit_rows = []

    total_scans = len(audit_rows)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("PromptPurify scans", str(total_scans), "from audit log")
    with col2:
        critical = sum(
            1 for r in audit_rows
            if "severity=Critical" in r.get("Details", "") or "severity=High" in r.get("Details", "")
        )
        st.metric("High-severity signals", str(critical))
    with col3:
        owasp = [r for r in audit_rows if "OWASP" in r.get("Action", "")]
        score_hint = owasp[-1]["Details"] if owasp else "Run OWASP scan"
        st.metric("Latest OWASP note", score_hint[:40] + ("…" if len(score_hint) > 40 else ""))

    st.markdown("---")
    st.subheader("Threat activity (sample trend)")

    if audit_rows:
        df = pd.DataFrame(audit_rows)

        # Robust timestamp parsing: handle ISO strings, epoch seconds, and milliseconds
        def parse_flexible(ts_series: pd.Series) -> pd.Series:
            # First, try standard parsing (ISO, common formats)
            parsed = pd.to_datetime(ts_series, errors="coerce", utc=False)

            # If many values failed, attempt to parse the failed entries as epoch seconds
            if parsed.isna().mean() > 0.4:
                mask = parsed.isna()
                try:
                    secs = pd.to_numeric(ts_series[mask], errors="coerce")
                    parsed_secs = pd.to_datetime(secs, errors="coerce", unit="s", utc=False)
                    parsed.loc[mask] = parsed_secs
                except Exception:
                    pass

            # For any remaining NaT entries, attempt milliseconds
            if parsed.isna().any():
                mask = parsed.isna()
                try:
                    msecs = pd.to_numeric(ts_series[mask], errors="coerce")
                    parsed_msecs = pd.to_datetime(msecs, errors="coerce", unit="ms", utc=False)
                    parsed.loc[mask] = parsed_msecs
                except Exception:
                    pass

            # Final fallback: try python-dateutil parser for remaining stringy timestamps
            if parsed.isna().any():
                try:
                    from dateutil import parser as _parser
                    for idx in parsed[parsed.isna()].index:
                        raw = ts_series.loc[idx]
                        try:
                            parsed_val = _parser.parse(str(raw))
                            parsed.loc[idx] = parsed_val
                        except Exception:
                            continue
                except Exception:
                    pass

            return parsed

        df["Date"] = parse_flexible(df["Timestamp"])
        # drop rows without valid dates
        df = df.dropna(subset=["Date"]).copy()

        if df.empty:
            # Fallback to last 7 days with zero counts
            dates = pd.date_range(end=pd.Timestamp.today(), periods=7)
            daily = pd.DataFrame({"Date": dates, "Scans": [0] * 7})
            fig = px.line(daily, x="Date", y="Scans", template="plotly_dark", line_shape="spline")
            fig.update_traces(line_color="#00e5ff")
        else:
            # Resample by day to produce a smooth time-series even with sparse timestamps
            daily = df.set_index("Date").resample("D").size().reset_index(name="Scans")
            fig = px.line(daily, x="Date", y="Scans", template="plotly_dark", line_shape="spline")
            fig.update_traces(line_color="#00e5ff", fill="tozeroy", fillcolor="rgba(0, 229, 255, 0.1)")
    else:
        dates = pd.date_range(end=pd.Timestamp.today(), periods=7)
        df = pd.DataFrame({"Date": dates, "Scans": [0] * 7})
        fig = px.line(df, x="Date", y="Scans", template="plotly_dark", line_shape="spline")
        fig.update_traces(line_color="#00e5ff")

    st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("Recent PromptPurify activity")
    if audit_rows:
        st.dataframe(pd.DataFrame(audit_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No PromptPurify scans logged yet. Run a scan from the other modules.")
