import pandas as pd
from pathlib import Path

file_path = Path("data/cloud_logs.csv")

df = pd.read_csv(file_path)

test_events = []

for i in range(6):
    test_events.append({
        "timestamp": f"2026-10-02 10:0{i}:00",
        "username": "test_user",
        "event_type": "LOGIN_FAILED",
        "source_ip": "192.0.2.99"
    })

test_df = pd.DataFrame(test_events)

# Keep a backup before modifying the dataset
backup_path = Path("data/cloud_logs_backup.csv")

if not backup_path.exists():
    df.to_csv(backup_path, index=False)

combined = pd.concat(
    [df, test_df],
    ignore_index=True
)

combined.to_csv(file_path, index=False)

print("Test login failures added successfully!")