import win32evtlog

def monitor_logs():
    log_type = "Security"
    server = "localhost"

    handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = win32evtlog.ReadEventLog(handle, flags, 0)

    for event in events[:10]:  # sample first 10
        print(f"Event ID: {event.EventID}")
        print(f"Source: {event.SourceName}")
        print(f"Time: {event.TimeGenerated}")
        print("-" * 30)

if __name__ == "__main__":
    monitor_logs()
