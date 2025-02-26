#!/usr/bin/env python3
# To RUN:
# nohup ./recovery-logs-from-s3.py -eps 10000 -min 2024-01-01T00:00:00 -max 2024-01-02T00:00:00 -o /tmp/recovery.json -log ./recovery.log -sz 400 -p s3 -e https://example.wasabisys.com -b my-bucket-name &

import gzip
import time
import json
import argparse
import re
import os
from datetime import datetime, timedelta
import boto3
import botocore
from botocore.exceptions import ClientError

def log(msg):
    now_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    final_msg = f"{now_date} wazuh-reinjection: {msg}"
    print(final_msg)
    if log_file:
        f_log.write(final_msg + "\n")


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
    f_log = open(log_file, 'a+')

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
#s3 = session.resource('s3', endpoint_url=args.s3_endpoint)
s3_client = session.client('s3', endpoint_url=args.s3_endpoint)
BUCKET_NAME = args.bucket

current_time = datetime(min_timestamp.year, min_timestamp.month, min_timestamp.day)
end_time     = datetime(max_timestamp.year, max_timestamp.month, max_timestamp.day)

output_file   = args.output_file
trimmed_alerts = open(output_file, 'w')

chunk = 0
while current_time <= end_time:
    # Build the path in your bucket. Example:
    #  s3://bucket-name/2024/Jan/ossec-archive-01.json.gz
    #
    # If your actual structure is different (e.g. 2024/01 or 2024/01/ossec-archive-2024-01-01.json.gz),
    # adjust accordingly.
    year_str  = str(current_time.year)            # "2024"
    month_str = month_dict[current_time.month]    # "Jan", "Feb", etc.
    day_str   = f"{current_time.day:02d}"         # "01", "02", etc.

    object_key = f"{year_str}/{month_str}/ossec-archive-{day_str}.json.gz"

    log(f"Checking for: s3://{BUCKET_NAME}/{object_key}")
    try:
        s3_client.head_object(Bucket=BUCKET_NAME, Key=object_key)
    except ClientError as e:
        if e.response['Error']['Code'] == '404' or e.response['Error']['Code'] == 'NoSuchKey':
            log(f"File not found in S3: {object_key}")
        else:
            log(f"Error accessing {object_key}: {str(e)}")
        current_time += timedelta(days=1)
        continue

    try:
        get_resp = s3_client.get_object(Bucket=BUCKET_NAME, Key=object_key)
    except ClientError as e:
        log(f"Error downloading {object_key}: {str(e)}")
        current_time += timedelta(days=1)
        continue

    daily_alerts = 0
    compressed_alerts = gzip.GzipFile(fileobj=get_resp['Body'])
    log(f"Reading file from S3: {object_key}")

    with compressed_alerts:
        for line in compressed_alerts:
            try:
                line_json = json.loads(line.decode("utf-8", "replace"))

                # Remove unnecessary part of the timestamp
                string_timestamp = line_json['timestamp'][:19]

                # Ensure timestamp integrity
                while len(line_json['timestamp'].split("+")[0]) < 23:
                    line_json['timestamp'] = line_json['timestamp'][:20] + "0" + line_json['timestamp'][20:]

                # Get the timestamp readable
                event_date = datetime.strptime(string_timestamp, '%Y-%m-%dT%H:%M:%S')

                # Check the timestamp belongs to the selected range
                if (event_date <= max_timestamp and event_date >= min_timestamp and line_json and 'data' in line_json and 'win' in line_json['data'] and 'eventInfo' in line_json['data']['win'] and 'resource' in line_json['data']['win']['eventInfo'] and line_json['data']['win']['eventInfo']['resource'] == "test@mail.com"):
                    chunk+=1
                    trimmed_alerts.write(json.dumps(line_json))
                    trimmed_alerts.write("\n")
                    trimmed_alerts.flush()
                    daily_alerts += 1
                    if chunk >= EPS_MAX:
                        chunk = 0
                        time.sleep(2)
                    if os.path.getsize(output_file) >= max_bytes:
                        trimmed_alerts.close()
                        log("Output file reached max size, setting it to zero and restarting")
                        time.sleep(EPS_MAX/100)
                        trimmed_alerts = open(output_file, 'w')

            except ValueError as e:
                print("Oops! Something went wrong reading: {}".format(line))
                print("This is the error: {}".format(str(e)))

        compressed_alerts.close()
        log("Extracted {0} alerts from day {1}-{2}-{3}".format(daily_alerts,current_time.day,month_dict[current_time.month],current_time.year))

    current_time += timedelta(days=1)

trimmed_alerts.close()