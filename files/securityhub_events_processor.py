"""
For processing data sent to Firehose by Cloudwatch Logs subscription filters.

Cloudwatch Logs sends to Firehose records that look like this:

{
  "messageType": "DATA_MESSAGE",
  "owner": "123456789012",
  "logGroup": "log_group_name",
  "logStream": "log_stream_name",
  "subscriptionFilters": [
    "subscription_filter_name"
  ],
  "logEvents": [
    {
      "id": "01234567890123456789012345678901234567890123456789012345",
      "timestamp": 1510109208016,
      "message": "log message 1"
    },
    {
      "id": "01234567890123456789012345678901234567890123456789012345",
      "timestamp": 1510109208017,
      "message": "log message 2"
    }
    ...
  ]
}

The code below will:

1) Parse the json
2) Set the result to ProcessingFailed for any record whose messageType is not DATA_MESSAGE, thus redirecting them to the
   processing error output. Such records do not contain any log events. You can modify the code to set the result to
   Dropped instead to get rid of these records completely.
3) For records whose messageType is DATA_MESSAGE, extract the individual log events from the logEvents field, and pass
   each one to the transformLogEvent method. You can modify the transformLogEvent method to perform custom
   transformations on the log events.
4) Concatenate the result from (3) together and set the result as the data of the record returned to Firehose. Note that
   this step will not add any delimiters. Delimiters should be appended by the logic within the transformLogEvent
   method.
5) Any additional records which exceed 6MB will be re-ingested back into Firehose.

"""

import base64
import boto3
import json
import sys

IS_PY3 = sys.version_info[0] == 3

def transformLogEvent(log_event, source):
    """Transform each log event.

    The default implementation below just extracts the message and appends a newline to it.

    Args:
    log_event (dict): The original log event. Structure is {"id": str, "timestamp": long, "message": str}

    Returns:
    str: The transformed log event.
    """
    return_event = {}
    return_event['sourcetype'] = 'aws:cloudwatchlogs'
    return_event['source'] = source
    return_event['event'] = log_event['message']
    return json.dumps(return_event) + '\n'


def processRecords(records):
    for r in records:
        data = json.loads(base64.b64decode(r['data']))
        recId = r['recordId']
        return_event = {}
        # Setting a default `sourcetype` in case not caught by anything else
        st = data['source'].replace(".", ":") + ":securityhub:finding"
        config_findings = 0
        cloudtrail_findings = 0
        securityhub_findings = 0
        guardduty_findings = 0
        other_findings = 0

        print(f"data[detail-type]: {data['detail-type']}")
        print(f"data[source]: {data['source']}")

        # Config
        if (data['detail-type'] == 'Config Configuration Item Change'):
            st = 'aws:config:notification'
            config_findings += 1

        # SecurityHub
        if ((data['detail-type'] == 'Security Hub Findings - Imported') or (data['detail-type'] == 'Security Hub Insight Results') or (data['detail-type'] == 'Security Hub Insight Results')):
            st = 'aws:securityhub:finding'
            securityhub_findings += 1

        print(f'GuardDuty Findings: {guardduty_findings} / Config Findings: {config_findings} / CloudTrail Findings: {cloudtrail_findings} / SecurityHub Findings: {securityhub_findings} / Other Findings: {other_findings}')
        return_event['sourcetype'] = st
        return_event['event'] = data['detail']

        if IS_PY3:
            # base64 encode api changes in python3 to operate exclusively on byte-like objects and bytes
            data = base64.b64encode(json.dumps(return_event).encode('utf-8')).decode()
        else:
            data = base64.b64encode(json.dumps(return_event))
        yield {
            'data': data,
            'result': 'Ok',
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
    # print('Lambda invoked...')
    # print('Event:')
    # print(event)
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