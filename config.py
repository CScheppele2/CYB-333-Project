# config.py

SECURITY_LOG = "Security"
POLL_INTERVAL = 30  # seconds between checks
OUTPUT_DIR = "output"

MONITORED_EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4720: "User Account Created",
    4726: "User Account Deleted",
}

FAILED_LOGON_THRESHOLD = 5
