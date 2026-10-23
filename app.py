import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3

from pathlib import Path
from log_analyser import analyze_logs
from database import save_alerts


# ---------------------------------
# PAGE CONFIGURATION
# ---------------------------------

st.set_page_config(
    page_title="Cloud Security Monitoring",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------
# CUSTOM CSS
# ---------------------------------

st.markdown("""
<style>

.stApp {
    background-color: #0E1117;
    color: white;
}

h1, h2, h3 {
    color: #00D4FF;
}

div[data-testid="stMetric"] {
    background-color: #1C2333;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #30363D;
}

</style>
""", unsafe_allow_html=True)


# ---------------------------------
# FILE PATHS
# ---------------------------------

DATA_FILE = Path("data/cloud_logs.csv")

REPORT_FILE = Path(
    "reports/security_alerts.csv"
)

DB_FILE = Path(
    "data/security_events.db"
)


# ---------------------------------
# SIDEBAR
# ---------------------------------

st.sidebar.title("🛡️ Cloud Security")

st.sidebar.markdown(
    "### Security Operations Center"
)

st.sidebar.success("Monitoring Dashboard")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Security Alerts",
        "Database",
        "Reports"
    ]
)


# ---------------------------------
# LOAD DATA
# ---------------------------------

@st.cache_data
def load_logs():

    if not DATA_FILE.exists():
        return pd.DataFrame()

    df = pd.read_csv(DATA_FILE)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    return df


@st.cache_data
def load_alerts():

    if not REPORT_FILE.exists():
        return pd.DataFrame()

    return pd.read_csv(REPORT_FILE)


logs = load_logs()
alerts = load_alerts()


# ---------------------------------
# REFRESH ANALYSIS
# ---------------------------------

if st.sidebar.button(
    "🔄 Run Security Analysis"
):

    try:

        analyze_logs()

        save_alerts()

        st.cache_data.clear()

        st.sidebar.success(
            "Security analysis completed!"
        )

        st.rerun()

    except Exception as e:

        st.sidebar.error(str(e))


# ---------------------------------
# DASHBOARD
# ---------------------------------

if page == "Dashboard":

    st.title(
        "☁️ Cloud Security Monitoring Dashboard"
    )

    st.write(
        "Advanced Cloud Security Analytics"
    )

    if logs.empty:

        st.warning(
            "No cloud security logs found."
        )

        st.stop()

    total_events = len(logs)

    failed_logins = (
        logs["event_type"] == "LOGIN_FAILED"
    ).sum()

    successful_logins = (
        logs["event_type"] == "LOGIN_SUCCESS"
    ).sum()

    high_alerts = (
        len(alerts)
        if not alerts.empty
        else 0
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        total_events
    )

    col2.metric(
        "Failed Logins",
        failed_logins
    )

    col3.metric(
        "Successful Logins",
        successful_logins
    )

    col4.metric(
        "Security Alerts",
        high_alerts
    )

    st.divider()

    # EVENT DISTRIBUTION

    st.subheader(
        "📊 Security Event Distribution"
    )

    event_counts = (
        logs["event_type"]
        .value_counts()
        .reset_index()
    )

    event_counts.columns = [
        "Event Type",
        "Count"
    ]

    fig = px.pie(
        event_counts,
        names="Event Type",
        values="Count",
        title="Cloud Security Events",
        hole=0.4
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # FAILED LOGIN IP ADDRESSES

    st.subheader(
        "🌍 Failed Login Sources"
    )

    failed = logs[
        logs["event_type"] == "LOGIN_FAILED"
    ]

    ip_counts = (
        failed["source_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    ip_counts.columns = [
        "IP Address",
        "Failed Attempts"
    ]

    fig2 = px.bar(
        ip_counts,
        x="IP Address",
        y="Failed Attempts",
        title="Top Failed Login Sources"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )

    # RECENT LOGS

    st.subheader(
        "📋 Recent Security Events"
    )

    st.dataframe(
        logs.sort_values(
            "timestamp",
            ascending=False
        ).head(100),
        use_container_width=True
    )


# ---------------------------------
# SECURITY ALERTS PAGE
# ---------------------------------

elif page == "Security Alerts":

    st.title("🚨 Security Alerts")

    if alerts.empty:

        st.success(
            "No security alerts detected."
        )

    else:

        st.error(
            f"{len(alerts)} security alerts detected!"
        )

        st.dataframe(
            alerts,
            use_container_width=True
        )

        st.subheader(
            "Alert Severity Distribution"
        )

        severity_counts = (
            alerts["severity"]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        fig = px.bar(
            severity_counts,
            x="Severity",
            y="Count"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ---------------------------------
# DATABASE PAGE
# ---------------------------------

elif page == "Database":

    st.title("🗄️ Security Database")

    if DB_FILE.exists():

        try:

            with sqlite3.connect(DB_FILE) as conn:

                db_data = pd.read_sql_query(
                    "SELECT * FROM security_alerts",
                    conn
                )

            st.success(
                "SQLite Database Connected!"
            )

            st.dataframe(
                db_data,
                use_container_width=True
            )

        except Exception as e:

            st.error(
                f"Database error: {e}"
            )

    else:

        st.warning(
            "Database not found."
        )


# ---------------------------------
# REPORTS PAGE
# ---------------------------------

elif page == "Reports":

    st.title("📄 Security Reports")

    st.write(
        "Download Cloud Security Analysis Reports"
    )

    if not logs.empty:

        csv_logs = logs.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "📥 Download Cloud Logs",
            data=csv_logs,
            file_name="cloud_logs_report.csv",
            mime="text/csv"
        )

    if not alerts.empty:

        csv_alerts = alerts.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "🚨 Download Security Alerts",
            data=csv_alerts,
            file_name="security_alerts_report.csv",
            mime="text/csv"
        )


# ---------------------------------
# FOOTER
# ---------------------------------

st.divider()

st.caption(
    "Cloud Security Monitoring Dashboard | "
    "Educational Cybersecurity Project"
)