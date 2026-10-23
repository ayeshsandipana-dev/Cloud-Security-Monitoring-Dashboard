import pandas as pd
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

users = [
    "admin",
    "security_admin",
    "developer",
    "cloud_user",
    "guest"
]

event_types = [
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "ACCESS_DENIED",
    "API_CALL",
    "FILE_ACCESS"
]

ip_addresses = [
    "192.0.2.10",
    "192.0.2.20",
    "198.51.100.15",
    "203.0.113.25",
    "203.0.113.50"
]

logs = []

start_time = datetime(2026, 10, 1)

for i in range(1000):

    timestamp = start_time + timedelta(
        minutes=i
    )

    user = random.choice(users)

    event = random.choice(event_types)

    ip = random.choice(ip_addresses)

    logs.append({
        "timestamp": timestamp,
        "username": user,
        "event_type": event,
        "source_ip": ip
    })

df = pd.DataFrame(logs)

Path("data").mkdir(exist_ok=True)

df.to_csv(
    "data/cloud_logs.csv",
    index=False
)

print("Cloud Security Dataset Generated Successfully!")

print("Total Events:", len(df))