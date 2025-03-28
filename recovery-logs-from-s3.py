#!/usr/bin/env python3
# To RUN:
# nohup ./recovery-logs-from-s3.py -eps 10000 -min 2024-01-01T00:00:00 -max 2024-01-02T00:00:00 -o /tmp/recovery.json -log ./recovery.log -sz 400 -p s3 -e https://example.wasabisys.com -b my-bucket-name &

import gzip
import time
import json
import argparse
import re
import os
import tempfile
import hashlib
from datetime import datetime, timedelta
import boto3
import botocore
from botocore.exceptions import ClientError

# Ensure f_log is defined globally to avoid "possibly unbound" errors.
f_log = None

def log(msg):
    now_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    final_msg = f"{now_date} wazuh-reinjection: {msg}"
    print(final_msg)
    if f_log:
        try:
            f_log.write(final_msg + "\n")
            f_log.flush()
        except Exception as e:
            print(f"Error writing to log file: {e}")

month_dict = ['Null','Jan','Feb','Mar','Apr','May','Jun',
              'Jul','Aug','Sep','Oct','Nov','Dec']

parser = argparse.ArgumentParser(description='Reinjection script')
parser.add_argument('-eps','--eps', metavar='eps', type=int, default=400, required=False,
                    help='Events per second. Default 400.')
parser.add_argument('-min','--min_timestamp', metavar='min_timestamp', type=str, required=True,
                    help='Min timestamp. Format: YYYY-MM-DDTHH:MM:SS')
parser.add_argument('-max','--max_timestamp', metavar='max_timestamp', type=str, required=True,
                    help='Max timestamp. Format: YYYY-MM-DDTHH:MM:SS')
parser.add_argument('-o','--output_file', metavar='output_file', type=str, required=True,
                    help='Output filename.')
parser.add_argument('-log','--log_file', metavar='log_file', type=str, required=False,
                    help='Log file path.')
parser.add_argument('-sz','--max_size', metavar='max_size', type=float, default=1.0, required=False,
                    help='Max output file size in GB. Default=1 GB')

parser.add_argument('-p', '--aws_profile', metavar='aws_profile', type=str, required=True,
                    help='AWS profile to use (e.g., s3).')
parser.add_argument('-e', '--s3_endpoint', metavar='s3_endpoint', type=str, required=True,
                    help='S3 endpoint URL (e.g., https://example.wasabisys.com).')
parser.add_argument('-b', '--bucket', metavar='bucket', type=str, required=True,
                    help='S3 bucket name (e.g., my-bucket-name).')

args = parser.parse_args()

log_file = None
if args.log_file:
    log_file = args.log_file
    try:
        f_log = open(log_file, 'a+')
    except Exception as e:
        print(f"Error opening log file {args.log_file}: {e}")
        log_file = None

EPS_MAX = args.eps
if EPS_MAX <= 0:
    log("Error: EPS must be > 0")
    exit(1)

max_bytes = int(args.max_size * 1024 * 1024 * 1024)
if max_bytes <= 0:
    log("Error: max_size must be > 0")
    exit(1)

# Validate & convert min/max timestamps
try:
    min_timestamp = datetime.strptime(args.min_timestamp, '%Y-%m-%dT%H:%M:%S')
except ValueError:
    log("Error: Incorrect format for min_timestamp")
    exit(1)

try:
    max_timestamp = datetime.strptime(args.max_timestamp, '%Y-%m-%dT%H:%M:%S')
except ValueError:
    log("Error: Incorrect format for max_timestamp")
    exit(1)

session = boto3.Session(profile_name=args.aws_profile)
s3_client = session.client('s3', endpoint_url=args.s3_endpoint)
BUCKET_NAME = args.bucket

def download_and_verify(object_key):
    """Download the compressed file from S3 into a temporary file using streaming,
       and verify the download via ContentLength and checksum (using ETag if available).
       Returns the temporary filename if successful, else None."""
    retry_attempts = 3
    for attempt in range(1, retry_attempts + 1):
        try:
            head_resp = s3_client.head_object(Bucket=BUCKET_NAME, Key=object_key)
            expected_size = head_resp['ContentLength']
            expected_etag = head_resp.get('ETag', None)
            if expected_etag:
                expected_etag = expected_etag.strip('"')
        except Exception as e:
            log(f"Error during head_object for {object_key}: {e}")
            return None

        try:
            get_resp = s3_client.get_object(Bucket=BUCKET_NAME, Key=object_key)
        except Exception as e:
            log(f"Error during get_object for {object_key}: {e}, attempt {attempt}")
            time.sleep(2)
            continue

        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_filename = tmp_file.name
                bytes_read = 0
                while True:
                    chunk_data = get_resp['Body'].read(1024 * 1024)  # 1MB chunks
                    if not chunk_data:
                        break
                    tmp_file.write(chunk_data)
                    bytes_read += len(chunk_data)

            if bytes_read != expected_size:
                log(f"File size mismatch for {object_key}: expected {expected_size}, got {bytes_read}, attempt {attempt}")
                os.remove(tmp_filename)
                time.sleep(2)
                continue

            # Checksum verification: compute MD5 checksum of the downloaded file
            md5_hash = hashlib.md5()
            with open(tmp_filename, 'rb') as f:
                for data in iter(lambda: f.read(4096), b""):
                    md5_hash.update(data)
            actual_checksum = md5_hash.hexdigest()
            if expected_etag and expected_etag != actual_checksum:
                log(f"Checksum mismatch for {object_key}: expected {expected_etag}, got {actual_checksum}, attempt {attempt}")
                os.remove(tmp_filename)
                time.sleep(2)
                continue

            log(f"Download and verification succeeded for {object_key} on attempt {attempt}")
            return tmp_filename

        except Exception as e:
            log(f"Error during streaming download for {object_key}: {e}, attempt {attempt}")
            time.sleep(2)
            continue

    return None

output_file = args.output_file
try:
    trimmed_alerts = open(output_file, 'w')
except Exception as e:
    log(f"Error opening output file {output_file}: {e}")
    exit(1)

current_time = datetime(min_timestamp.year, min_timestamp.month, min_timestamp.day)
end_time     = datetime(max_timestamp.year, max_timestamp.month, max_timestamp.day)
chunk = 0

while current_time <= end_time:
    # Build the path in your bucket.
    year_str  = str(current_time.year)            # "2024"
    month_str = month_dict[current_time.month]      # "Jan", "Feb", etc.
    day_str   = f"{current_time.day:02d}"            # "01", "02", etc.
    object_key = f"{year_str}/{month_str}/ossec-archive-{day_str}.json.gz"

    log(f"Checking for: s3://{BUCKET_NAME}/{object_key}")
    try:
        s3_client.head_object(Bucket=BUCKET_NAME, Key=object_key)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code in ['404', 'NoSuchKey']:
            log(f"File not found in S3: {object_key}")
        else:
            log(f"Error accessing {object_key}: {str(e)}")
        current_time += timedelta(days=1)
        continue
    except Exception as e:
        log(f"Unexpected error during head_object for {object_key}: {e}")
        current_time += timedelta(days=1)
        continue

    tmp_filename = download_and_verify(object_key)
    if tmp_filename is None:
        log(f"Failed to download and verify {object_key} after retries")
        current_time += timedelta(days=1)
        continue

    daily_alerts = 0
    try:
        # Open the temporary file and use streaming decompression.
        with open(tmp_filename, 'rb') as f:
            with gzip.GzipFile(fileobj=f) as gz:
                for line in gz:
                    try:
                        line_json = json.loads(line.decode("utf-8", "replace"))

                        # Remove unnecessary part of the timestamp
                        string_timestamp = line_json['timestamp'][:19]

                        # Ensure timestamp integrity
                        while len(line_json['timestamp'].split("+")[0]) < 23:
                            line_json['timestamp'] = line_json['timestamp'][:20] + "0" + line_json['timestamp'][20:]

                        # Get the timestamp readable
                        event_date = datetime.strptime(string_timestamp, '%Y-%m-%dT%H:%M:%S')

                        # Check the timestamp belongs to the selected range and the event matches our criteria
                        if (event_date <= max_timestamp and event_date >= min_timestamp and 
                            line_json and 'data' in line_json and 'win' in line_json['data'] and 
                            'eventInfo' in line_json['data']['win'] and 'resource' in line_json['data']['win']['eventInfo'] and 
                            line_json['data']['win']['eventInfo']['resource'] == "test@mail.com" and 
                            'system' in line_json['data']['win'] and 'eventID' in line_json['data']['win']['system'] and 
                            line_json['data']['win']['system']['eventID'] in [302, 303]):
                            
                            chunk += 1
                            try:
                                trimmed_alerts.write(json.dumps(line_json) + "\n")
                                trimmed_alerts.flush()
                            except Exception as e:
                                log(f"Error writing to output file: {e}")
                            
                            daily_alerts += 1
                            if chunk >= EPS_MAX:
                                chunk = 0
                                time.sleep(2)
                            try:
                                if os.path.getsize(output_file) >= max_bytes:
                                    trimmed_alerts.close()
                                    log("Output file reached max size, setting it to zero and restarting")
                                    time.sleep(EPS_MAX/100)
                                    trimmed_alerts = open(output_file, 'w')
                            except Exception as e:
                                log(f"Error checking/rotating output file size: {e}")
                    except ValueError as e:
                        log(f"Error processing line: {line}. Error: {e}")
                    except Exception as e:
                        log(f"Unexpected error processing line: {line}. Error: {e}")
    except Exception as e:
        log(f"Error processing decompressed content from {object_key}: {e}")

    # Clean up the temporary file after processing.
    try:
        os.remove(tmp_filename)
    except Exception as e:
        log(f"Error removing temporary file {tmp_filename}: {e}")

    log("Extracted {0} alerts from day {1}-{2}-{3}".format(daily_alerts, current_time.day, month_dict[current_time.month], current_time.year))
    current_time += timedelta(days=1)

try:
    trimmed_alerts.close()
except Exception as e:
    log(f"Error closing output file: {e}")

if f_log:
    try:
        f_log.close()
    except Exception as e:
        print(f"Error closing log file: {e}")
