
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from pathlib import Path

app = Flask(__name__)
app.secret_key = "soc-dashboard-local-demo-key"

# Database location
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "soc_incidents.db"


# Connect to SQLite
def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# Dashboard home page
@app.route("/")
def dashboard():

    connection = get_db_connection()

    # Total incidents
    total = connection.execute(
        "SELECT COUNT(*) FROM incidents"
    ).fetchone()[0]

    # Critical incidents
    critical = connection.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'"
    ).fetchone()[0]

    # Open incidents
    open_count = connection.execute(
        "SELECT COUNT(*) FROM incidents WHERE incident_status = 'Open'"
    ).fetchone()[0]

    # Resolved incidents
    resolved = connection.execute(
        "SELECT COUNT(*) FROM incidents WHERE incident_status = 'Resolved'"
    ).fetchone()[0]

    # Retrieve incident records
    incidents = connection.execute("""
        SELECT *
        FROM incidents
        ORDER BY priority_score DESC, incident_id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "index.html",
        total=total,
        critical=critical,
        open_count=open_count,
        resolved=resolved,
        incidents=incidents
    )


# Update incident status
@app.route("/update-status/<int:incident_id>", methods=["POST"])
def update_status(incident_id):

    new_status = request.form.get("status", "")

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    if new_status not in allowed_statuses:
        flash("Invalid incident status.", "error")
        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    result = connection.execute("""
        UPDATE incidents
        SET incident_status = ?
        WHERE incident_id = ?
    """, (new_status, incident_id))

    connection.commit()
    connection.close()

    if result.rowcount:
        flash("Incident status updated successfully!", "success")
    else:
        flash("Incident not found.", "error")

    return redirect(url_for("dashboard"))


# Assign incident to analyst
@app.route("/assign/<int:incident_id>", methods=["POST"])
def assign_incident(incident_id):

    analyst = request.form.get("analyst", "").strip()

    if not analyst or len(analyst) > 100:
        flash("Enter a valid analyst name.", "error")
        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    result = connection.execute("""
        UPDATE incidents
        SET assigned_to = ?
        WHERE incident_id = ?
    """, (analyst, incident_id))

    connection.commit()
    connection.close()

    if result.rowcount:
        flash("Incident assigned successfully!", "success")
    else:
        flash("Incident not found.", "error")

    return redirect(url_for("dashboard"))


if __name__ == "__main__":

    if not DATABASE_PATH.exists():
        raise FileNotFoundError(
            "SOC database not found. Run incident_manager.py first."
        )

    app.run(debug=True)
