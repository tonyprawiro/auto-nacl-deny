import json
import base64
import gzip
import time
import sys
import socket
import pymysql
import os
import logging
from datetime import datetime

rds_dbhostname  = os.environ['dbhostname']
rds_dbport  = os.environ['dbport']
rds_dbusername = os.environ['dbusername']
rds_dbpassword = os.environ['dbpassword']
rds_dbname = os.environ['dbname']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

try:
    conn = pymysql.connect(rds_dbhostname, user=rds_dbusername, passwd=rds_dbpassword, db=rds_dbname, connect_timeout=5)
except pymysql.MySQLError as e:
    logger.error("ERROR: Unexpected error: Could not connect to MySQL instance.")
    logger.error(e)
    sys.exit()


def lambda_handler(event, context):

    # Ingest log entries and aggregate to sql table
    b64encodeddata = event['awslogs']['data']
    zippeddata = base64.b64decode(b64encodeddata)
    stringdata = gzip.decompress(zippeddata).decode('utf-8')
    jsondata = json.loads(stringdata)
    ipaddresses = {}
    for logEvent in jsondata['logEvents']:
        ip = logEvent['extractedFields']['ip']
        try:
            ipaddresses[ip]['count'] += 1
        except:
            ipaddresses[ip] = { "count": 1 }
        ipaddresses[ip]['timestamp'] = int(datetime.now().timestamp())
    for ip in ipaddresses:
        with conn.cursor() as cur:
            cur.execute('insert into accesslogstats (timestamp, ip, count) values (%s, %s, %s)', (
                ipaddresses[ip]['timestamp'],
                ip,
                ipaddresses[ip]['count']
            ))
        conn.commit()

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

