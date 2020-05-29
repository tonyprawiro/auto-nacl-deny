# auto-nacl-deny

Solution to automatically insert deny rule of IP addresses to VPC NACL based on application log

# Use Case

In some scenarios, you need a quick way to block a certain traffic source network or IP addresses after discovering potential abuse or high volume of requests from a software log, such as web server access log. VPC Network Access Control list allows you to implement this by adding deny rules of the IP address or range (CIDR).

Amazon Web Application Firewall (WAF) also offers rate-limiting ACL rules and more features. However, AWS WAF protects Cloudfront distribution, Application Load Balancer, and API Gateway. If the application is not protected by any of those services, the only possible way to reject the traffic is by implementing VPC NACL deny rule.

Using combination of multiple AWS Services, automation can be built so that you don't have to manually analyze the IP traffic and manually insert NACL rules. You can define a threshold of maximum allowed request rate and duration, to allow the automation to regulate itself.


# Architecture

[asd](images/arch.png)

- Your application lives within a subnet protected by Network Access Control List

- Ship your application access logs to Cloudwatch Logs using the Cloudwatch Agent or Systems Manager (SSM) Agent

- Create Cloudwatch Logs Subscription to send log entries to a Lambda function (_"ingestor"_) that parses, aggregates, and append entries to an SQL database

- Create Cloudwatch Events Schedule Rule that triggers a Lambda function (_"watcher"_). The function housekeeps the SQL database to remove old entries, creates a list of IP addresses that exceeds the predefined threshold, and maintains the VPC NACL according to this list

# Implementation Details

This section describes a use case of this automation against a default Apache web server access log

## EC2 Instance Role Permission

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

## Cloudwatch Agent Configuration

Section of `awslogs.conf` config file that defines log file to be shipped to Cloudwatch Logs:

```
...
[/var/log/httpd]
datetime_format = %d/%b/%Y:%H:%M:%S %z
file = /var/log/httpd/access_log*
buffer_duration = 5000
log_stream_name = {instance_id}
initial_position = start_of_file
log_group_name = /var/log/httpd/access_log
...
```

Ensure the correct region is set in `awscli.conf` file

## Subscription filter to "ingestor" Lambda function

The following filter pattern is used so that Cloudwatch can identify fields to be extracted and passed to the Lambda function as event object parameters

```
[ ip, remotehost, userid, timestamp, request, statuscode, bytes, useragent ]
```

[asd](images/logfilter.png)

## "ingestor" Lambda function

The function logic is as the following:

[asd](images/ingestor.png)

The function receive the payload from Cloudwatch Logs subscription in the event object. The payload is compressed and encoded, so it needs to be decoded and extracted first:

```
b64encodeddata = event['awslogs']['data']
zippeddata = base64.b64decode(b64encodeddata)
stringdata = gzip.decompress(zippeddata).decode('utf-8')
jsondata = json.loads(stringdata)
```

Next, iterate through log events, and aggregate the entries based on Log Event's timestamp. You may choose to aggregate based on Apache log entry's timestamp instead. It's important to aggregate log entries, so that we can keep the number of records in database low.

```
ipaddresses = {}
for logEvent in jsondata['logEvents']:
	ip = logEvent['extractedFields']['ip']
	try:
		ipaddresses[ip]['count'] += 1
	except:
		ipaddresses[ip] = { "count": 1 }
	ipaddresses[ip]['timestamp'] = int(datetime.now().timestamp())
```

Finally, insert the aggregated entries into the SQL database:

```
for ip in ipaddresses:
	with conn.cursor() as cur:
		cur.execute('insert into accesslogstats (timestamp, ip, count) values (%s, %s, %s)', (
			ipaddresses[ip]['timestamp'],
			ip,
			ipaddresses[ip]['count']
		))
	conn.commit()
```

This function needs to connect to RDS SQL database that lives within a VPC. So the following must be configured:

1. Include `pymysql` pip package as part of the Lambda function's package when updating the function code

```
$ pip install pymysql -t .
$ zip -r lambda_function.zip .
$ aws lambda update-function-code --function-name ingestor --zip-file lambda_function.zip
```

2. Pass SQL connection details to the function as parameters. It will be better to store connection details in Secrets Manager or SSM Parameter Store so you avoid storing passwords in function parameter.

[asd](images/lambdaenv.png)

Connect to the database

```
rds_dbhostname  = os.environ['dbhostname']
rds_dbport  = os.environ['dbport']
rds_dbusername = os.environ['dbusername']
rds_dbpassword = os.environ['dbpassword']
rds_dbname = os.environ['dbname']

try:
    conn = pymysql.connect(rds_dbhostname, user=rds_dbusername, passwd=rds_dbpassword, db=rds_dbname, connect_timeout=5)
except pymysql.MySQLError as e:
    logger.error("ERROR: Unexpected error: Could not connect to MySQL instance.")
    logger.error(e)
    sys.exit()
```

3. Attach "AWSLambdaVPCAccessExecutionRole" IAM Policy to the Lambda's IAM Role so that it can send function log to Cloudwatch Logs and manage ENIs to connect to the VPC. This IAM Policy is an AWS-managed policy, so you don't have to create it.

## RDS MySQL Database

The database contains just a single table that stores aggregated application log entries. It is defined as the following:

```
CREATE TABLE accesslogstats (
  id INT PRIMARY KEY AUTO_INCREMENT,
  timestamp BIGINT,
  ip VARCHAR(50),
  count INT
);
```

The "timestamp" column is in epoch but you may also store in other timestamp format, such as MySQL's TIMESTAMP data type.

The "ip" column is the IP addresses as discovered in the log event.

The "count" column is the number of entries associated with the "ip" address.

The reason SQL database is used here is because we will need to run aggregation and GROUP queries in order to rank the IP addresses and determine how to manipulate the VPC NACL.

## Cloudwatch Events Schedule Rule

Create an Event Rule, configure a Schedule to invoke the target, "watcher" Lambda function.

[asd](images/cweventrule.png)

## "watcher" Lambda function

The function's logic is as the following:

[asd](watcher.png)

The function is invoked by the Cloudwatch Events.

First step is to remove old entries from the database:

```
timestamp_24hrsago = int(datetime.now().timestamp()) - 86400
with conn.cursor() as cur:
	cur.execute('delete from accesslogstats where timestamp < %s', (timestamp_24hrsago))
conn.commit()
```

The function also has the following variables set that defines the maximum request rate per IP addresses and the range of NACL RuleNumber managed by the function.

```
denyrulecap = 10        # The max number of rules managed by this function
maxtotalcount = 100     # The threshold of total request within a specified duration
rulenumberstart = 9000  # 9000, 9001, 9002, etc
rulenumbermax   = 9050  # the highest RuleNumber managed by this function
```

Summarize the entries from the database using the following SQL query. The duration can be customized and is best set as variable instead of hardcoded.

```
...
timestamp_1hrago = int(datetime.now().timestamp()) - 3600
...
cur.execute('SELECT ip, SUM(count) as totalcount FROM accesslogstats WHERE timestamp > %s group by ip HAVING totalcount > %s ORDER BY totalcount DESC LIMIT %s;', (timestamp_1hrago, maxtotalcount, denyrulecap))
```

The query ranks the number of access, highest returned first.

Store the result is a dictionary that stores the IP address and total count.

If "maxtotalcount" is 100 and duration is 3600s, then the threshold is 100 requests / hour.

The RuleNumber corresponds to the VPC NACL rule's RuleNumber field. The function needs a predefined rule number range to manage. This is so that it doesn't accidentally change or remove existing rules created by someone else. This also means, we need to be deliberate when setting the RuleNumber of our rules in the NACL.

Then, iterate the dictionary. For each item in the dictionary, a corresponding RuleNumber is set. For instance, the first item gets RuleNumber 9000, second item gets 9001, and so on. 

Next, check if the RuleNumber already exists in the VPC NACL with the same CIDR range.

If yes, then replace it using "replace_entry" API call.

```
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
```

Otherwise, create a new entry by calling "create_entry".

```
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
```

Finally, delete unnecessary NACL rules within the managed range.

```
for entry in networkacl.entries:
	if not entry['Egress']:
		if entry['RuleNumber'] > maxaclrulenumber and entry['RuleNumber'] < rulenumbermax:
			print("Delete rulenumber " + str(entry['RuleNumber']))
			networkacl.delete_entry(Egress = False, RuleNumber = entry['RuleNumber'])
``` 

Just like the "ingestor" function, the "watcher" function needs to connect to RDS SQL database that lives within a VPC. So the following must be configured:

1. Include `pymysql` pip package as part of the Lambda function's package when updating the function code

```
$ pip install pymysql -t .
$ zip -r lambda_function.zip .
$ aws lambda update-function-code --function-name ingestor --zip-file lambda_function.zip
```

2. Pass SQL connection details to the function as parameters. It will be better to store connection details in Secrets Manager or SSM Parameter Store so you avoid storing passwords in function parameter.

[asd](images/lambdaenv.png)

Connect to the database

```
rds_dbhostname  = os.environ['dbhostname']
rds_dbport  = os.environ['dbport']
rds_dbusername = os.environ['dbusername']
rds_dbpassword = os.environ['dbpassword']
rds_dbname = os.environ['dbname']

try:
    conn = pymysql.connect(rds_dbhostname, user=rds_dbusername, passwd=rds_dbpassword, db=rds_dbname, connect_timeout=5)
except pymysql.MySQLError as e:
    logger.error("ERROR: Unexpected error: Could not connect to MySQL instance.")
    logger.error(e)
    sys.exit()
```

3. Attach "AWSLambdaVPCAccessExecutionRole" IAM Policy to the Lambda's IAM Role so that it can send function log to Cloudwatch Logs and manage ENIs to connect to the VPC. This IAM Policy is an AWS-managed policy, so you don't have to create it.

In addition to the above:

4. The function will also need to manipulate VPC NACL entries. So the following IAM permission needs to be added to the function's Role:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:ReplaceNetworkAclEntry",
                "ec2:DescribeNetworkAcls",
                "ec2:CreateNetworkAclEntry",
                "ec2:DeleteNetworkAclEntry"
            ],
            "Resource": "*"
        }
    ]
}
```

5. The Lambda function needs to perform EC2 API calls . It has to be associated with private subnet that has a route to NAT Gateway or NAT Instance in another public subnet.

[asd](images/lambdaprivatesubnet.png)

## VPC Network Access Control List

Network ACL is associated with a subnet. An ACL is divided into inbound and outbound rules. Each rule has CIDR, ICMP type code, Port number, Protocol, Action, and RuleNumber. Action can be "allow" or "deny".

With a limited number of rules per Network ACL available, it is important to plan the rule-numbering properly.

By default, there is maximum 20 rules per network ACL. This limit can be increased to 40, however, there might be performance impact due to increased workload to process the additional rules.

We want to ensure that there is still some room for you to add rules based on other criterias, outside of this automation. One way to achieve this is by allocating a predefined range, for example, 9000 to 9009. This also means you need to add overlapping "allow" rules above this predefined range. For example, 10000 or above.

If your "allow" rules were given RuleNumber below the range, VPC NACL will immediately allow the traffic to pass through and the "deny" rules will not be evaluated.

[asd](images/nacl.png)



# References

[1] AWS Security Best Practices Whitepaper 

https://d1.awsstatic.com/whitepapers/Security/AWS_Security_Best_Practices.pdf

[2] Amazon VPC User Guide | Network ACLs

https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html

[3] Amazon Cloudwatch | Real-time Processing of Log Data with Subscriptions 

https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html

[4] Amazon Cloudwatch | Cloudwatch Logs Agent Reference

https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AgentReference.html

[5] Amazon VPC | Quotas

https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html#vpc-limits-nacls

[6] Amazon VPC | Network ACL basics

https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html