import pandas as pd
from pathlib import Path

DATA_FILE = Path("data/cloud_logs.csv")
REPORT_FILE = Path("reports/security_alerts.csv")

def analyze_logs():
    if not DATA_FILE.exists():
        raise FileNotFoundError("Cloud logs not found!")

    df = pd.read_csv(DATA_FILE)

    required = {
        "timestamp", "username",
        "event_type", "source_ip"
    }

    if not required.issubset(df.columns):
        raise ValueError("Missing required CSV columns")

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    df = df.dropna(
        subset=["timestamp", "source_ip", "event_type"]
    )

    df = df.sort_values("timestamp")

    failed = df[df["event_type"] == "LOGIN_FAILED"]

    alerts = []

    # Detect repeated failed logins:
    # 5 or more failures from the same IP in 10 minutes.
    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")

        for _, row in group.iterrows():
            start = row["timestamp"] - pd.Timedelta(minutes=10)

            window = group[
                (group["timestamp"] >= start) &
                (group["timestamp"] <= row["timestamp"])
            ]

            if len(window) >= 5:
                alerts.append({
                    "timestamp": row["timestamp"],
                    "source_ip": ip,
                    "alert_type": "REPEATED_LOGIN_FAILURES",
                    "severity": "HIGH",
                    "failed_attempts": len(window)
                })

    alerts_df = pd.DataFrame(
        alerts,
        columns=[
            "timestamp", "source_ip", "alert_type",
            "severity", "failed_attempts"
        ]
    )

    Path("reports").mkdir(exist_ok=True)

    alerts_df.to_csv(REPORT_FILE, index=False)

    print("\nCLOUD SECURITY ANALYSIS")
    print("------------------------")
    print("Total Events:", len(df))
    print("Failed Logins:", len(failed))
    print("Security Alerts:", len(alerts_df))
    print("Report:", REPORT_FILE)

    return alerts_df


if __name__ == "__main__":
    analyze_logs()