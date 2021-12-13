import base64
import boto3
import json
import sys

IS_PY3 = sys.version_info[0] == 3

def processRecords(records):
for r in records:
data = json.loads(base64.b64decode(r['data']))
recId = r['recordId']
return_event = {}
#st = data['source'].replace(".", ":") + "aws:firehose:cloudwatchevents"

config_findings = 0
cloudtrail_findings = 0
securityhub_findings = 0
guardduty_findings = 0
other_findings = 0

#print(f"data[detail-type]: {data['detail-type']}")
#print(f"data[source]: {data['source']}")

# Others

if (data['source'] == 'aws.batch'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'CloudWatch Events Scheduled Event'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'CodePipeline Pipeline Execution State Change'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'CodeCommit Repository State Change') or (data['detail-type'] == 'CodeCommit Comment on Commit') or (data['detail-type'] == 'CodeCommit Comment on Pull Request')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'CodePipeline Stage Execution State Change') or (data['detail-type'] == 'CodePipeline Action Execution State Change')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'CodeBuild Build State Change') or (data['detail-type'] == 'CodeBuild Build Phase Change')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'CodeDeploy Deployment State-change Notification') or (data['detail-type'] == 'CodeDeploy Instance State-change Notification')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'Config Rules Compliance Change') or (data['detail-type'] == 'Config Rules Re-evaluation Status') or (data['detail-type'] == 'Config Configuration Snapshot Delivery Status') or (data['detail-type'] == 'Config Configuration History Delivery Status')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'DLM Policy State Change'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'EC2 Instance State-change Notification') or (data['detail-type'] == 'EBS Volume Notification') or (data['detail-type'] == 'EBS Snapshot Notification') or (data['detail-type'] == 'EC2 Spot Instance Interruption Warning')):
st =  'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'ECS Task State Change') or (data['detail-type'] == 'ECS Container Instance State Change')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'EMR Auto Scaling Policy State Change') or (data['detail-type'] == 'EMR Step Status Change') or (data['detail-type'] == 'EMR Cluster State Change') or (data['detail-type'] == 'EMR Instance Group State Change') or (data['detail-type'] == 'EMR Instance Fleet State Change') or (data['detail-type'] == 'EMR Instance Group Status Notification')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'GameLift Matchmaking Event'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'Glue Job State Change') or (data['detail-type'] == 'Glue Crawler State Change') or (data['detail-type'] == 'Glue Job Run Status')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'AWS Health Event'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'KMS Imported Key Material Expiration') or (data['detail-type'] == 'KMS CMK Rotation') or (data['detail-type'] == 'KMS CMK Deletion')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'Macie Alert'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'MediaStore Object State Change') or (data['detail-type'] == 'MediaStore Container State Change')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'MediaConvert Job State Change'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'MediaLive Channel State Change') or (data['detail-type'] == 'MediaLive Channel Alert')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'OpsWorks Instance State Change') or (data['detail-type'] == 'OpsWorks Command State Change') or (data['detail-type'] == 'OpsWorks Deployment State Change') or (data['detail-type'] == 'OpsWorks Alert')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'Signer Job Status Change'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'Server Migration Job State Change'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'EC2 State Manager Association State Change') or (data['detail-type'] == 'EC2 State Manager Instance Association State Change') or (data['detail-type'] == 'EC2 Command Status-change Notification') or (data['detail-type'] == 'EC2 Command Invocation Status-change Notification') or (data['detail-type'] == 'Maintenance Window State-change Notification') or (data['detail-type'] == 'Maintenance Window Target Registration Notification') or (data['detail-type'] == 'Maintenance Window Execution State-change Notification') or (data['detail-type'] == 'Maintenance Window Task Execution State-change Notification') or (data['detail-type'] == 'Maintenance Window Task Target Invocation State-change Notification') or (data['detail-type'] == 'Maintenance Window Task Registration Notification') or (data['detail-type'] == 'EC2 Automation Step Status-change Notification') or (data['detail-type'] == 'EC2 Automation Execution Status-change Notification') or (data['detail-type'] == 'Parameter Store Change') or (data['detail-type'] == 'Configuration Compliance State Change') or (data['detail-type'] == 'Inventory Resource State Change')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if ((data['detail-type'] == 'Storage Gateway File Upload Event') or (data['detail-type'] == 'Storage Gateway Refresh Cache Event')):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'Transcribe Job State Change'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

if (data['detail-type'] == 'WorkSpaces Access'):
st = 'aws:firehose:cloudwatchevents'
other_findings += 1

# Config
if (data['detail-type'] == 'Config Configuration Item Change'):
st = 'aws:firehose:cloudwatchevents'
config_findings += 1

# CloudTrail
# if ((data['detail-type'] == 'AWS API Call via CloudTrail') or (data['detail-type'] == 'AWS Console Sign In via CloudTrail')):
if ((data['detail-type'] == 'AWS Console Sign In via CloudTrail')):
st = 'aws:cloudtrail'
cloudtrail_findings += 1

# return_event['timestamp'] = data['time']
# return_event['time'] = data['time']
return_event['sourcetype'] = st
return_event['source'] = data['source']
return_event['event'] = data['detail']
print(return_event)

# print(data['detail'])
# print(data['source'])
# print(data['time'])
# print(return_event)

if IS_PY3:
# base64 encode api changes in python3 to operate exclusively on byte-like objects and bytes
data = base64.b64encode(json.dumps(return_event).encode('utf-8')).decode()
else:
data = base64.b64encode(json.dumps(return_event))


if len(data) <= 600000:
yield {
'data': data,
'result': 'Ok',
'recordId': recId
}
else:
yield {
'result': 'ProcessingFailed',
'recordId': recId
}


def putRecordsToFirehoseStream(streamName, records, client, attemptsMade, maxAttempts):
failedRecords = []
codes = []
errMsg = ''
# if put_record_batch throws for whatever reason, response['xx'] will error out, adding a check for a valid
# response will prevent this
response = None
try:
response = client.put_record_batch(DeliveryStreamName=streamName, Records=records)
except Exception as e:
failedRecords = records
errMsg = str(e)

# if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
if not failedRecords and response and response['FailedPutCount'] > 0:
for idx, res in enumerate(response['RequestResponses']):
# (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
if 'ErrorCode' not in res or not res['ErrorCode']:
continue

codes.append(res['ErrorCode'])
failedRecords.append(records[idx])

errMsg = 'Individual error codes: ' + ','.join(codes)

if len(failedRecords) > 0:
if attemptsMade + 1 < maxAttempts:
print('Some records failed while calling PutRecordBatch to Firehose stream, retrying. %s' % (errMsg))
putRecordsToFirehoseStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
else:
raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))


def putRecordsToKinesisStream(streamName, records, client, attemptsMade, maxAttempts):
failedRecords = []
codes = []
errMsg = ''
# if put_records throws for whatever reason, response['xx'] will error out, adding a check for a valid
# response will prevent this
response = None
try:
response = client.put_records(StreamName=streamName, Records=records)
except Exception as e:
failedRecords = records
errMsg = str(e)

# if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
if not failedRecords and response and response['FailedRecordCount'] > 0:
for idx, res in enumerate(response['Records']):
# (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
if 'ErrorCode' not in res or not res['ErrorCode']:
continue

codes.append(res['ErrorCode'])
failedRecords.append(records[idx])

errMsg = 'Individual error codes: ' + ','.join(codes)

if len(failedRecords) > 0:
if attemptsMade + 1 < maxAttempts:
print('Some records failed while calling PutRecords to Kinesis stream, retrying. %s' % (errMsg))
putRecordsToKinesisStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
else:
raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))


def createReingestionRecord(isSas, originalRecord):
if isSas:
return {'data': base64.b64decode(originalRecord['data']), 'partitionKey': originalRecord['kinesisRecordMetadata']['partitionKey']}
else:
return {'data': base64.b64decode(originalRecord['data'])}


def getReingestionRecord(isSas, reIngestionRecord):
if isSas:
return {'Data': reIngestionRecord['data'], 'PartitionKey': reIngestionRecord['partitionKey']}
else:
return {'Data': reIngestionRecord['data']}


def handler(event, context):
isSas = 'sourceKinesisStreamArn' in event
streamARN = event['sourceKinesisStreamArn'] if isSas else event['deliveryStreamArn']
region = streamARN.split(':')[3]
streamName = streamARN.split('/')[1]
records = list(processRecords(event['records']))
projectedSize = 0
dataByRecordId = {rec['recordId']: createReingestionRecord(isSas, rec) for rec in event['records']}
putRecordBatches = []
recordsToReingest = []
totalRecordsToBeReingested = 0

for idx, rec in enumerate(records):
if rec['result'] != 'Ok':
continue
projectedSize += len(rec['data']) + len(rec['recordId'])
# 6000000 instead of 6291456 to leave ample headroom for the stuff we didn't account for
if projectedSize > 6000000:
totalRecordsToBeReingested += 1
recordsToReingest.append(
getReingestionRecord(isSas, dataByRecordId[rec['recordId']])
)
records[idx]['result'] = 'Dropped'
del(records[idx]['data'])

# split out the record batches into multiple groups, 500 records at max per group
if len(recordsToReingest) == 500:
putRecordBatches.append(recordsToReingest)
recordsToReingest = []

if len(recordsToReingest) > 0:
# add the last batch
putRecordBatches.append(recordsToReingest)

# iterate and call putRecordBatch for each group
recordsReingestedSoFar = 0
if len(putRecordBatches) > 0:
client = boto3.client('kinesis', region_name=region) if isSas else boto3.client('firehose', region_name=region)
for recordBatch in putRecordBatches:
if isSas:
putRecordsToKinesisStream(streamName, recordBatch, client, attemptsMade=0, maxAttempts=20)
else:
putRecordsToFirehoseStream(streamName, recordBatch, client, attemptsMade=0, maxAttempts=20)
recordsReingestedSoFar += len(recordBatch)
print('Reingested %d/%d records out of %d' % (recordsReingestedSoFar, totalRecordsToBeReingested, len(event['records'])))
else:
print('No records to be reingested')

return {"records": records}
