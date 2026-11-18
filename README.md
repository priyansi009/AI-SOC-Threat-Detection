# AI-Powered SOC Threat Detection & Incident Response Platform

An AI-powered cybersecurity project designed to analyze security logs, detect suspicious activities, and support threat monitoring using Python and Machine Learning.

## Tech Stack
- Python
- Pandas, NumPy
- Scikit-learn
- Flask
- SQL
- HTML, CSS, JavaScript

## Project Structure
```text
AI-SOC-Threat-Detection/
├── dataset/
├── src/
├── requirements.txt
├── .gitignore
└── README.md
```

## Development Phases

### Phase 1: Security Log Collection & Preprocessing
- Created a simulated security log dataset.
- Identified missing values and removed duplicates.
- Cleaned and normalized log data.
- Extracted date and hour from timestamps.
- Generated a processed dataset.

**Output:** `processed_logs.csv`

### Phase 2: Security Event & Anomaly Detection
- Implement rule-based failed-login detection.
- Apply Isolation Forest for anomaly detection.
- Generate alerts for suspicious activities.

**Output:** `threat_alerts.csv`

### Phase 3: Threat Classification & Alert Prioritization
- Classify detected threats.
- Assign severity levels to security alerts.
- Prioritize suspicious activities.

### Phase 4: Incident Tracking
- Integrate SQL for incident storage.
- Track alerts and investigation status.
- Maintain incident records.

### Phase 5: SOC Monitoring Dashboard
- Develop a Flask-based dashboard.
- Display security alerts and threat statistics.
- Provide incident monitoring and tracking.

### Phase 6: Testing & Evaluation
- Test detection performance.
- Evaluate model results.
- Finalize project documentation.

## Project Goal
To develop an AI-assisted SOC platform that streamlines security log analysis, identifies potential threats, and supports incident investigation.

## Current Status
Phase 1: Completed

