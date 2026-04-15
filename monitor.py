# monitor.py

import time
import win32evtlog

from alerts import parse_event, build_alerts
from config import SECURITY_LOG, POLL_INTERVAL, MONITORED_EVENT_IDS
from utils import save_alert


def build_query():
    """Build an XPath query for the event IDs we want to monitor."""
    conditions = " or ".join([f"EventID={event_id}" for event_id in MONITORED_EVENT_IDS])
    return f"*[System[({conditions})]]"


def fetch_events():
    """Fetch recent Windows event log entries."""
    query = build_query()
    handle = win32evtlog.EvtQuery(SECURITY_LOG, win32evtlog.EvtQueryReverseDirection, query)

    events = []
    while True:
        results = win32evtlog.EvtNext(handle, 10)
        if not results:
            break

        for event in results:
            xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            parsed = parse_event(xml)
            events.append(parsed)

        if len(events) >= 50:
            break

    return events


def main():
    print("Starting Automated Windows Security Monitoring Tool...")
    print("Monitoring Windows Security log for suspicious events.\n")

    seen_records = set()
    failed_logons = {}

    try:
        while True:
            events = fetch_events()

            for event in reversed(events):
                record_id = event["record_id"]

                if record_id in seen_records:
                    continue

                seen_records.add(record_id)

                alerts = build_alerts(event, failed_logons)

                for alert in alerts:
                    print(f"[{alert['severity']}] {alert['summary']}")
                    print(f"    Details: {alert['details']}")
                    print(f"    Time: {alert['time']}\n")
                    save_alert(alert)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")


if __name__ == "__main__":
    main()
