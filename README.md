# CYB-333-Project
# Automated Windows Security Monitoring and Alerting Tool

## Project Overview
This project is a Python-based security automation tool designed to monitor Windows Security event logs in real time. It identifies suspicious activity such as failed logon attempts, successful logons, account creation, and account deletion events.

## Features
- Monitors Windows Security logs
- Detects key Windows event IDs
- Alerts on suspicious activity
- Saves alerts to a CSV file
- Built for CYB 333 Security Automation

## Current Event IDs Monitored
- 4624: Successful Logon
- 4625: Failed Logon
- 4720: User Account Created
- 4726: User Account Deleted

## How to Run
1. Install requirements:
   ```bash
   pip install -r requirements.txt
