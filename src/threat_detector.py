
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

# Get project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Input and output file locations
input_path = BASE_DIR / "dataset" / "processed_logs.csv"
output_path = BASE_DIR / "dataset" / "threat_alerts.csv"

# Load processed security logs
logs = pd.read_csv(input_path)

print("\n========== SOC THREAT DETECTION ==========")

# Check required columns
required_columns = [
    "timestamp",
    "username",
    "source_ip",
    "status",
    "hour"
]

missing_columns = [
    column for column in required_columns
    if column not in logs.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )

# Normalize relevant text columns
logs["status"] = logs["status"].fillna("").astype(str).str.strip().str.lower()
logs["source_ip"] = logs["source_ip"].fillna("Unknown").astype(str).str.strip()
logs["username"] = logs["username"].fillna("Unknown").astype(str).str.strip()

# Identify failed login attempts
logs["failed_login"] = (logs["status"] == "failed").astype(int)

# Count failed attempts from each IP address
logs["ip_failed_attempts"] = (
    logs.groupby("source_ip")["failed_login"].transform("sum")
)

# Count failed attempts for each username
logs["user_failed_attempts"] = (
    logs.groupby("username")["failed_login"].transform("sum")
)

# RULE-BASED DETECTION
# Flag IP addresses with 5 or more failed login attempts

FAILED_LOGIN_THRESHOLD = 5

logs["brute_force_suspected"] = (
    (logs["failed_login"] == 1) &
    (logs["ip_failed_attempts"] >= FAILED_LOGIN_THRESHOLD)
)

print("\nRule-Based Detection:")
print(
    "Suspicious failed login records:",
    logs["brute_force_suspected"].sum()
)

# MACHINE LEARNING ANOMALY DETECTION

# Prepare numerical features
features = logs[
    [
        "hour",
        "failed_login",
        "ip_failed_attempts",
        "user_failed_attempts"
    ]
].copy()

# Handle missing and invalid feature values
features = features.apply(pd.to_numeric, errors="coerce")
features = features.fillna(0)

# Train Isolation Forest
model = IsolationForest(
    n_estimators=100,
    contamination=0.15,
    random_state=42
)

model.fit(features)

# Predict anomalies
# -1 = anomaly
#  1 = normal

logs["anomaly_prediction"] = model.predict(features)

logs["is_anomaly"] = logs["anomaly_prediction"] == -1

# Calculate anomaly scores
logs["anomaly_score"] = model.decision_function(features)

print("\nMachine Learning Detection:")
print("Anomalous records:", logs["is_anomaly"].sum())

# COMBINE DETECTION RESULTS

logs["alert_generated"] = (
    logs["brute_force_suspected"] |
    logs["is_anomaly"]
)

alerts = logs[logs["alert_generated"]].copy()

# Assign alert reasons
def get_alert_reason(row):
    reasons = []

    if row["brute_force_suspected"]:
        reasons.append("Repeated failed login attempts")

    if row["is_anomaly"]:
        reasons.append("Unusual activity pattern detected")

    return "; ".join(reasons)


alerts["alert_reason"] = alerts.apply(
    get_alert_reason,
    axis=1
)

# Assign severity
alerts["severity"] = alerts["brute_force_suspected"].map(
    {True: "High", False: "Medium"}
)

# Save alerts
alerts.to_csv(output_path, index=False)

# DISPLAY RESULTS
print("\n========== DETECTION RESULTS ==========")

print("Total log records:", len(logs))
print("Total generated alerts:", len(alerts))

print("\nAlert severity distribution:")
if not alerts.empty:
    print(alerts["severity"].value_counts())
else:
    print("No alerts generated.")

print("\nAlert details:")

if not alerts.empty:
    print(
        alerts[
            [
                "timestamp",
                "username",
                "source_ip",
                "status",
                "alert_reason",
                "severity",
                "anomaly_score"
            ]
        ].to_string(index=False)
    )

print("\nThreat alerts saved successfully!")
print("Output file:", output_path)
