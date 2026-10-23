import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH = Path("data/security_events.db")
REPORT_PATH = Path("reports/security_alerts.csv")

def save_alerts():

    if not REPORT_PATH.exists():
        print("No alert report found.")
        return

    df = pd.read_csv(REPORT_PATH)

    if df.empty:
        print("No alerts to save.")
        return

    with sqlite3.connect(DB_PATH) as conn:
        df.to_sql(
            "security_alerts",
            conn,
            if_exists="replace",
            index=False
        )

    print("Security alerts saved to SQLite database!")


if __name__ == "__main__":
    save_alerts()