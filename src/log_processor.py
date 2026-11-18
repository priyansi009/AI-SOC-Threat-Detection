
import pandas as pd
from pathlib import Path

# Get project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Dataset location
file_path = BASE_DIR / "dataset" / "security_logs.csv"

# Read security logs
logs = pd.read_csv(file_path)

print("\n========== SOC LOG ANALYSIS ==========")

# Check dataset
print("\nDataset Information:")
logs.info()

# Check missing values
print("\nMissing Values:")
print(logs.isnull().sum())

# Remove duplicate records
logs = logs.drop_duplicates()

# Clean text columns
text_columns = [
    "username",
    "source_ip",
    "event_type",
    "status",
    "label"
]

for column in text_columns:
    logs[column] = (
        logs[column].astype("string").str.strip().str.lower()
    )

# Convert timestamps
logs["timestamp"] = pd.to_datetime(
    logs["timestamp"],
    errors="coerce"
)

# Remove invalid timestamps
logs = logs.dropna(subset=["timestamp"])

# Extract date and hour
logs["hour"] = logs["timestamp"].dt.hour
logs["date"] = logs["timestamp"].dt.date

# Save processed dataset
output_path = BASE_DIR / "dataset" / "processed_logs.csv"

logs.to_csv(output_path, index=False)

# Display analysis
print("\n========== ANALYSIS RESULTS ==========")

print("Total records:", len(logs))

print("\nLogin status distribution:")
print(logs["status"].value_counts())

print("\nSecurity label distribution:")
print(logs["label"].value_counts())

print("\nEvents by IP address:")
print(logs["source_ip"].value_counts())

print("\nProcessed dataset saved successfully!")
