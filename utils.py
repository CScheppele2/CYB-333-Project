# utils.py

import csv
import os
from config import OUTPUT_DIR


def ensure_output_dir():
    """Create the output folder if it does not already exist."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def save_alert(alert):
    """Save alert data to a CSV file."""
    ensure_output_dir()
    file_path = os.path.join(OUTPUT_DIR, "alerts.csv")

    file_exists = os.path.exists(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["time", "event_id", "severity", "summary", "details"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(alert)
