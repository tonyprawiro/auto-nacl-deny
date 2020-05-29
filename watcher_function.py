import json
import base64
import gzip
import time
import sys
import socket
import pymysql
import os
import logging
import boto3
from datetime import datetime

rds_dbhostname  = os.environ['dbhostname']
rds_dbport  = os.environ['dbport']
rds_dbusername = os.environ['dbusername']
rds_dbpassword = os.environ['dbpassword']
rds_dbname = os.environ['dbname']

denyrulecap = 10
maxtotalcount = 100
rulenumberstart = 9000 # 9000, 9001, 9002, etc
rulenumbermax   = 9050

logger = logging.getLogger()
logger.setLevel(logging.INFO)

try:
    conn = pymysql.connect(rds_dbhostname, user=rds_dbusername, passwd=rds_dbpassword, db=rds_dbname, connect_timeout=5)
except pymysql.MySQLError as e:
    logger.error("ERROR: Unexpected error: Could not connect to MySQL instance.")
    logger.error(e)
    sys.exit()


def lambda_handler(event, context):

    # Housekeeping, remove old entries
    timestamp_24hrsago = int(datetime.now().timestamp()) - 86400
    with conn.cursor() as cur:
        cur.execute('delete from accesslogstats where timestamp < %s', (timestamp_24hrsago))
    conn.commit()

    # Summarize entries
    ipaddresses = {}
    timestamp_1hrago = int(datetime.now().timestamp()) - 3600
    totalentries = 0
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute('SELECT ip, SUM(count) as totalcount FROM accesslogstats WHERE timestamp > %s group by ip HAVING totalcount > %s ORDER BY totalcount DESC LIMIT %s;', (timestamp_1hrago, maxtotalcount, denyrulecap))
        for row in cur:
            totalentries += 1
            ipaddresses[row['ip']] = { "count": row['totalcount']}
            print("To block " + row["ip"] + "/32")

    maxaclentries = min(totalentries, denyrulecap) # e.g. if 10
    maxaclrulenumber = rulenumberstart + maxaclentries - 1 # 9000 + 10 -1

    ec2 = boto3.resource("ec2")
    # network acls
    networkacls = os.environ['networkacls'].split(',')
    for networkaclid in networkacls:

        print("nacl_id = " + networkaclid)
        networkacl = ec2.NetworkAcl(networkaclid)
        networkacl.load()

        # apply inbound rules based on number of deny rule cap
        i = 0
        for ip in ipaddresses:

            # rulenumber for this IP
            rulenumbertoset = rulenumberstart + i

            print("IP = " + ip + ", RuleNumber = " + str(rulenumbertoset))

            # does the rulenumber exist in the entries ?
            rulenumberexists = False
            samecidr = False
            for entry in networkacl.entries:
                if not entry['Egress']:
                    if entry['RuleNumber'] == rulenumbertoset:
                        rulenumberexists = True
                        if entry['CidrBlock'] == ip + "/32":
                            samecidr = True

            if not rulenumberexists:
                # create_entry
                print("Create entry in NACL")
                networkacl.create_entry(
                    CidrBlock = ip + "/32",
                    Egress = False,
                    IcmpTypeCode = { "Code": -1, "Type": -1},
                    PortRange = {
                        "From": 0,
                        "To": 65535
                    },
                    Protocol = "-1",
                    RuleAction = "deny",
                    RuleNumber = rulenumbertoset
                )
            else:
                if not samecidr:
                    # replace entry
                    print("Replace entry in NACL")
                    networkacl.replace_entry(
                        CidrBlock = ip + "/32",
                        Egress = False,
                        IcmpTypeCode = { "Code": -1, "Type": -1},
                        PortRange = {
                            "From": 0,
                            "To": 65535
                        },
                        Protocol = "-1",
                        RuleAction = "deny",
                        RuleNumber = rulenumbertoset
                    )
                else:
                    print("CIDR range is same, not replaced")
            i += 1

        # delete 900x entries that exceed the cap
        # e.g. if cap is 10, then max is 9009
        print("Deleting entries between " + str(maxaclrulenumber) + " and " + str(rulenumbermax) + " (non-inclusive)")
        for entry in networkacl.entries:
            if not entry['Egress']:
                if entry['RuleNumber'] > maxaclrulenumber and entry['RuleNumber'] < rulenumbermax:
                    print("Delete rulenumber " + str(entry['RuleNumber']))
                    networkacl.delete_entry(Egress = False, RuleNumber = entry['RuleNumber'])

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

