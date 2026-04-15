# alerts.py

import xml.etree.ElementTree as ET
from config import FAILED_LOGON_THRESHOLD


def parse_event(xml_text):
    """Parse Windows event XML into a Python dictionary."""
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    root = ET.fromstring(xml_text)

    system = root.find("e:System", namespace)

    event_id = int(system.find("e:EventID", namespace).text)
    record_id = int(system.find("e:EventRecordID", namespace).text)
    computer = system.find("e:Computer", namespace).text

    time_created_element = system.find("e:TimeCreated", namespace)
    time_created = time_created_element.attrib.get("SystemTime", "Unknown")

    event_data = {}
    for data in root.findall(".//e:EventData/e:Data", namespace):
        key = data.attrib.get("Name", "Unknown")
        value = data.text if data.text else ""
        event_data[key] = value

    return {
        "event_id": event_id,
        "record_id": record_id,
        "computer": computer,
        "time_created": time_created,
        "data": event_data,
    }


def build_alerts(event, failed_logons):
    """Create alerts based on event ID and event details."""
    alerts = []
    event_id = event["event_id"]
    data = event["data"]

    if event_id == 4625:
        username = data.get("TargetUserName", "Unknown")
        ip_address = data.get("IpAddress", "Unknown")

        key = ip_address if ip_address not in ("", "-", "Unknown") else username
        failed_logons[key] = failed_logons.get(key, 0) + 1
        count = failed_logons[key]

        alerts.append({
            "time": event["time_created"],
            "event_id": event_id,
            "severity": "Medium",
            "summary": f"Failed logon for user '{username}' from '{ip_address}'",
            "details": f"Failed login count for this source/user: {count}"
        })

        if count >= FAILED_LOGON_THRESHOLD:
            alerts.append({
                "time": event["time_created"],
                "event_id": event_id,
                "severity": "High",
                "summary": f"Possible brute-force activity detected from '{key}'",
                "details": f"Failed login threshold reached: {count} attempts"
            })

    elif event_id == 4624:
        username = data.get("TargetUserName", "Unknown")
        ip_address = data.get("IpAddress", "Unknown")

        alerts.append({
            "time": event["time_created"],
            "event_id": event_id,
            "severity": "Low",
            "summary": f"Successful logon for user '{username}' from '{ip_address}'",
            "details": "Successful login recorded"
        })

    elif event_id == 4720:
        new_user = data.get("TargetUserName", "Unknown")
        creator = data.get("SubjectUserName", "Unknown")

        alerts.append({
            "time": event["time_created"],
            "event_id": event_id,
            "severity": "High",
            "summary": f"New user account '{new_user}' was created",
            "details": f"Account created by: {creator}"
        })

    elif event_id == 4726:
        deleted_user = data.get("TargetUserName", "Unknown")
        actor = data.get("SubjectUserName", "Unknown")

        alerts.append({
            "time": event["time_created"],
            "event_id": event_id,
            "severity": "High",
            "summary": f"User account '{deleted_user}' was deleted",
            "details": f"Account deleted by: {actor}"
        })

    return alerts
