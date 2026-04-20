# CYB-333-Project
# Automated Windows Security Monitoring and Alerting Tool

## Project Overview
This project is a Python-based security automation tool designed to monitor Windows event logs and detect suspicious activity. The goal is to automate log analysis and alert users to potential security threats such as failed login attempts or unusual system behavior.

## Features
- Windows Event Log monitoring
- Filtering based on security-related Event IDs
- Detection of suspicious activity (e.g., failed logins)
- Real-time alerting via console output
- Option to export results to a file

## Technologies Used
- Python
- Windows Event Log APIs (win32evtlog)
- GitHub for version control

## Setup Instructions

### Requirements
- Python 3.x
- Windows OS
- Required libraries:

### How to Run
1. Clone the repository:
git clone https://github.com/CScheppele2/CYB-333-Project.git
2. Navigate to project folder:
cd CYB-333-Project
3. Run the script:
python main.py

## Project Structure
CYB-333-Project/
│── main.py
│── monitor.py
│── alerts.py
│── README.md

## Notes
- This tool is for educational purposes
- Do not expose sensitive system data publicly
- Do not upload API keys or credentials

## Future Improvements
- GUI dashboard
- Email/SMS alerts
- Integration with SIEM tools
- Real-time monitoring enhancements
