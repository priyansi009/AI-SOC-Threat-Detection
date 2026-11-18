
import sqlite3
from pathlib import Path

# Get project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database location
database_path = BASE_DIR / "database" / "soc_incidents.db"

# Connect to database
connection = sqlite3.connect(database_path)
cursor = connection.cursor()


# Display all incidents
def view_incidents():

    cursor.execute("""
        SELECT incident_id, username, source_ip,
               threat_category, severity,
               incident_status, assigned_to
        FROM incidents
        ORDER BY priority_score DESC
    """)

    records = cursor.fetchall()

    print("\n========== ALL INCIDENTS ==========")

    if not records:
        print("No incidents found.")
        return

    for record in records:
        print("\nIncident ID:", record[0])
        print("Username:", record[1])
        print("Source IP:", record[2])
        print("Threat:", record[3])
        print("Severity:", record[4])
        print("Status:", record[5])
        print("Assigned To:", record[6])


# Search for an incident
def search_incident():

    incident_id = input("Enter Incident ID: ").strip()

    if not incident_id.isdigit():
        print("Invalid incident ID.")
        return

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE incident_id = ?
    """, (int(incident_id),))

    record = cursor.fetchone()

    if record:
        print("\nIncident Found:")
        for column, value in zip(
            [description[0] for description in cursor.description],
            record
        ):
            print(f"{column}: {value}")

    else:
        print("Incident not found.")


# Update incident status
def update_status():

    incident_id = input("Enter Incident ID: ").strip()

    if not incident_id.isdigit():
        print("Invalid incident ID.")
        return

    new_status = input(
        "Enter status (Open/Investigating/Resolved): "
    ).strip().title()

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    if new_status not in allowed_statuses:
        print("Invalid status.")
        return

    cursor.execute("""
        UPDATE incidents
        SET incident_status = ?
        WHERE incident_id = ?
    """, (new_status, int(incident_id)))

    if cursor.rowcount > 0:
        connection.commit()
        print("Incident status updated successfully!")

    else:
        print("Incident ID not found.")


# Assign incident to an analyst
def assign_incident():

    incident_id = input("Enter Incident ID: ").strip()

    if not incident_id.isdigit():
        print("Invalid incident ID.")
        return

    analyst = input("Enter analyst name: ").strip()

    if not analyst:
        print("Analyst name cannot be empty.")
        return

    cursor.execute("""
        UPDATE incidents
        SET assigned_to = ?
        WHERE incident_id = ?
    """, (analyst, int(incident_id)))

    if cursor.rowcount > 0:
        connection.commit()
        print("Incident assigned successfully!")

    else:
        print("Incident ID not found.")


# Main menu
def main():

    while True:

        print("\n========== SOC INCIDENT MANAGEMENT ==========")
        print("1. View All Incidents")
        print("2. Search Incident")
        print("3. Update Incident Status")
        print("4. Assign Incident to Analyst")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            view_incidents()

        elif choice == "2":
            search_incident()

        elif choice == "3":
            update_status()

        elif choice == "4":
            assign_incident()

        elif choice == "5":
            print("Exiting Incident Management System.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":

    try:
        main()

    finally:
        connection.close()
