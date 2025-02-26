# Wazuh Log Recovery Scripts

This repository contains two Python scripts for recovering and filtering archived Wazuh logs:

recover-logs-from-s3.py
Fetches Gzipped logs directly from an S3-compatible service (e.g., Wasabi).
Applies date and field-based filtering before writing results to a local file.
recover-logs-from-wazuh.py
Reads Gzipped logs locally from a Wazuh manager’s /var/ossec/logs/archives/ directory (or a configurable path).
Applies similar filtering logic for date range and specific log fields.

Table of Contents

Prerequisites
Setting Up a Virtual Environment
Installation
Usage
Recover Logs From S3
Recover Logs From Wazuh Local Archives
Script Details
Filtering Logic
EPS Throttling
File Size Rotation

Python 3.6+
pip (Python package manager)
(Optional but recommended) A virtual environment for Python dependencies
For the S3-based script (recover-logs-from-s3.py), you’ll also need:

A valid AWS CLI profile (e.g., named s3, wasabi, or similar) configured in your ~/.aws/credentials file, or environment variables set for credentials.
Access to the S3-compatible endpoint (e.g., Wasabi) where logs are stored.
Setting Up a Virtual Environment

Create the virtual environment:
python3 -m venv .venv
Activate the virtual environment:
source .venv/bin/activate
(On Windows, use .venv\Scripts\activate instead.)
Installation

Once your virtual environment is active:

Install dependencies (for the S3 script, you need boto3; for local Wazuh logs, no additional external dependencies are required beyond standard libraries):
pip install boto3
(Optional) Freeze installed packages:
pip freeze > requirements.txt
Usage

Recover Logs From S3
Script: recover-logs-from-s3.py

Purpose: Read .json.gz files from S3 (Wasabi) for each day in a specified date range, filter them by a set of criteria, and write matching logs to a local output file.

Usage:
  ./recover-logs-from-s3.py
      -eps <events_per_second>
      -min <YYYY-MM-DDTHH:MM:SS>
      -max <YYYY-MM-DDTHH:MM:SS>
      -o   <output_file>
      -log <log_file>
      -sz  <max_output_size_in_GB>
      -p   <aws_profile>
      -e   <s3_endpoint_url>
      -b   <bucket_name>
Example:

nohup ./recover-logs-from-s3.py \
  -eps 10000 \
  -min 2024-01-01T00:00:00 \
  -max 2024-01-02T00:00:00 \
  -o /tmp/recovery.json \
  -log ./recovery.log \
  -sz 400 \
  -p s3 \
  -e https://example.wasabisys.com \
  -b my-bucket-name \
  &
This command:

Fetches logs day by day from 2024-01-01 up to 2024-01-02.
Throttles event processing to 10,000 events before sleeping 2 seconds.
Saves matching logs to /tmp/recovery.json, rotating the file if it exceeds 400 GB.
Logs script activity to ./recovery.log.
Uses your local AWS CLI profile named s3, connecting to https://example.wasabisys.com, and pulling files from the my-bucket-name bucket.
Recover Logs From Wazuh Local Archives
Script: recover-logs-from-wazuh.py

Purpose: Read .json.gz archives stored locally on a Wazuh manager (usually in /var/ossec/logs/archives/), filter them by date range, and optionally by specific fields.

Usage:
  ./recover-logs-from-wazuh.py
      -eps <events_per_second>
      -min <YYYY-MM-DDTHH:MM:SS>
      -max <YYYY-MM-DDTHH:MM:SS>
      -o   <output_file>
      -log <log_file>
      -sz  <max_output_size_in_GB>
      -w   <wazuh_path>
Example:

nohup ./recover-logs-from-wazuh.py \
  -eps 10000 \
  -min 2024-01-01T00:00:00 \
  -max 2025-01-01T00:00:00 \
  -o /tmp/recovery.json \
  -log ./recovery.log \
  -sz 400 \
  -w /var/ossec/ \
  &
Scans daily .json.gz files from 2024-01-01 to 2025-01-01.
Writes matching logs to /tmp/recovery.json, rotating if it surpasses 400 GB.
Logs activity to ./recovery.log.
Uses default Wazuh path /var/ossec/ (you can provide a custom path via -w if needed).
Script Details

Filtering Logic
Both scripts:

Extract each line from the daily .json.gz file.
Parse the line as JSON.
Extract the timestamp and compare it to the provided -min/-max range.
Optional filtering for certain fields, e.g.,
if line_json['data']['win']['eventInfo']['resource'] == "test@mail.com"
Adjust this if you have a different resource or event field to filter on.
EPS Throttling
Both scripts use a simple throttle approach:

chunk += 1
if chunk >= EPS_MAX:
    chunk = 0
    time.sleep(2)
This means that for every EPS_MAX events written, the script sleeps for 2 seconds. Adjust these values or logic as needed.

File Size Rotation
When the output file exceeds -sz (in GB), the script:

Closes the output file
Logs a “reached max size” message
Re-opens the same filename, effectively overwriting the file from zero bytes
If you want to keep multiple files, you need to implement a different naming scheme (e.g., appending an incremental counter).
