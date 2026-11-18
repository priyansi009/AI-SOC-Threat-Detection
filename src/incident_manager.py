
import pandas as pd
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Get project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Define file paths
input_path = BASE_DIR / "dataset" / "classified_alerts.csv"
database_path = BASE_DIR / "database" / "soc_incidents.db"

print("\n========== SOC INCIDENT MANAGEMENT ==========")

# Check whether Phase 3 output exists
if not input_path.exists():
    raise FileNotFoundError(
        f"Phase 3 output not found: {input_path}"
    )

# Load classified security alerts
alerts = pd.read_csv(input_path)

# Check required columns
required_columns = [
    "timestamp",
    "username",
    "source_ip",
    "threat_category",
    "severity",
    "priority_score"
]

missing_columns = [
    column for column in required_columns
    if column not in alerts.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )

# Convert missing values into safe database values
def clean_value(value):
    if pd.isna(value):
        return None
    return str(value).strip()

# Create a stable unique key for each alert
def generate_alert_key(row):
    identity = "|".join([
        clean_value(row.get("timestamp")) or "",
        clean_value(row.get("username")) or "",
        clean_value(row.get("source_ip")) or "",
        clean_value(row.get("threat_category")) or "",
        clean_value(row.get("alert_reason")) or ""
    ])

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()

# Connect to SQLite database
connection = sqlite3.connect(database_path)

cursor = connection.cursor()

# Create incidents table
cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT UNIQUE NOT NULL,
    timestamp TEXT,
    username TEXT,
    source_ip TEXT,
    threat_category TEXT,
    severity TEXT,
    priority_score INTEGER,
    alert_reason TEXT,
    login_status TEXT,
    incident_status TEXT DEFAULT 'Open'
        CHECK (incident_status IN (
            'Open', 'Investigating', 'Resolved'
        )),
    assigned_to TEXT DEFAULT 'Unassigned',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

# Insert alerts without duplicating previously imported records
inserted_count = 0

for _, row in alerts.iterrows():

    alert_key = generate_alert_key(row)

    cursor.execute("""
        INSERT OR IGNORE INTO incidents (
            alert_key,
            timestamp,
            username,
            source_ip,
            threat_category,
            severity,
            priority_score,
            alert_reason,
            login_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_key,
        clean_value(row.get("timestamp")),
        clean_value(row.get("username")),
        clean_value(row.get("source_ip")),
        clean_value(row.get("threat_category")),
        clean_value(row.get("severity")),
        int(row["priority_score"])
            if pd.notna(row["priority_score"]) else None,
        clean_value(row.get("alert_reason")),
        clean_value(row.get("status"))
    ))

    inserted_count += cursor.rowcount

# Save database changes
connection.commit()

# Display all stored incidents
cursor.execute("""
SELECT
    incident_id,
    username,
    source_ip,
    threat_category,
    severity,
    incident_status
FROM incidents
ORDER BY priority_score DESC
""")

records = cursor.fetchall()

print("\nNew incidents inserted:", inserted_count)
print("Total incidents stored:", len(records))

print("\nIncident Records:")

for record in records:
    print(record)

# Close database connection
connection.close()

print("\nIncident database updated successfully!")
print("Database location:", database_path)
