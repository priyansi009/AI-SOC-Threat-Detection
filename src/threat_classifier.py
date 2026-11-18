
import pandas as pd
from pathlib import Path

# Get project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Input and output paths
input_path = BASE_DIR / "dataset" / "threat_alerts.csv"
output_path = BASE_DIR / "dataset" / "classified_alerts.csv"

# Load Phase 2 alerts
alerts = pd.read_csv(input_path)

print("\n========== SOC THREAT CLASSIFICATION ==========")

# Verify required columns
required_columns = [
    "brute_force_suspected",
    "is_anomaly",
    "source_ip",
    "username"
]

missing_columns = [
    col for col in required_columns
    if col not in alerts.columns
]

if missing_columns:
    raise ValueError(f"Missing columns: {missing_columns}")

# Convert detection flags into consistent Boolean values
def convert_to_bool(series):
    return (
        series.astype(str)
        .str.strip()
        .str.lower()
        .isin(["true", "1", "yes"])
    )

alerts["brute_force_suspected"] = convert_to_bool(
    alerts["brute_force_suspected"]
)

alerts["is_anomaly"] = convert_to_bool(
    alerts["is_anomaly"]
)

# Classify threats
def classify_threat(row):

    if row["brute_force_suspected"] and row["is_anomaly"]:
        return "Multiple Indicators"

    elif row["brute_force_suspected"]:
        return "Potential Brute Force"

    elif row["is_anomaly"]:
        return "Anomalous Activity"

    else:
        return "General Security Alert"


alerts["threat_category"] = alerts.apply(
    classify_threat,
    axis=1
)

# Assign severity levels
def assign_severity(row):

    if row["brute_force_suspected"] and row["is_anomaly"]:
        return "Critical"

    elif row["brute_force_suspected"]:
        return "High"

    elif row["is_anomaly"]:
        return "Medium"

    else:
        return "Low"


alerts["severity"] = alerts.apply(
    assign_severity,
    axis=1
)

# Assign priority scores
priority_scores = {
    "Critical": 100,
    "High": 80,
    "Medium": 60,
    "Low": 30
}

alerts["priority_score"] = alerts["severity"].map(
    priority_scores
)

# Sort alerts by priority
alerts = alerts.sort_values(
    by="priority_score",
    ascending=False
)

# Save classified alerts
alerts.to_csv(output_path, index=False)

# Display results
print("\nTotal alerts classified:", len(alerts))

print("\nThreat Category Distribution:")
print(alerts["threat_category"].value_counts())

print("\nSeverity Distribution:")
print(alerts["severity"].value_counts())

print("\nPrioritized Security Alerts:")

display_columns = [
    "username",
    "source_ip",
    "threat_category",
    "severity",
    "priority_score"
]

print(alerts[display_columns].to_string(index=False))

print("\nClassified alerts saved successfully!")
print("Output file:", output_path)
