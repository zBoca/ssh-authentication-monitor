# SSH Authentication Monitor
A Python-based authentication monitoring tool that analyzes SSH authentication logs and detects potential brute-force attacks based on how many failed authentication attempts within a certain time window and creates a incident report if an issue is discovered

![Brute-force detection](screenshots/test_case_3.png)

## Overview
This project was created as a cybersecurity project to practice network monitoring, log analysis, event detection, and incident reporting in Linux using Python

The program parses SSH authentication logs, finds the failed password entries, groups them by their source IP, analyses them within a 60 second time window, classifies the severity, and generates an incident report for the detected threats.

## Features
 - SSH authentication log parsing
 - Failed authentication detection
 - Aggregating failed attempts by IP
 - Time-window based brute-force detection
 - Classifying severity
 - Incident report generation
 - Test scenarios for normal activity, malicious activity from one source, and malicious activity from multiple sources

## Screenshots
![Brute-force detection](screenshots/test_case_1.png)
![Brute-force detection](screenshots/test_case_2.png)
![Brute-force detection](screenshots/test_case_3.png)
![Brute-force detection](screenshots/incident_report.png)
