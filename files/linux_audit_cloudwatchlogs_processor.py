import base64
import json
import gzip
import boto3
import os
import sys
import re
import datetime
import decimal

IS_PY3 = sys.version_info[0] == 3
if IS_PY3:
    import io
else:
    import StringIO


def transformLogEvent(log_event,acct,arn,loggrp,logstrm,filterName):

    region_name=arn.split(':')[3]
    # note that the region_name is taken from the region for the Stream, this won't change if Cloudwatch from another account/region. Not used for this example function
    sourcetype="linux:audit"
    source="/var/log/audit"

    """
    testing stuff
    """
    #pattern= '\d+\.\d+'
    pattern='node=(\w+-\w+)|(\d+\.\d{3})'


    #test_string = 'node=cep-sas type=PROCTITLE msg=audit(1625047999.074:726274): proctitle=2F6'
    test_string = log_event['message']
    print(test_string)
    result = re.findall(pattern, test_string)
    print(result[0])
    x=result[0]
    x = ''.join(result[0])
    host = x.strip('"')
    print(host)
    x=result[1]
    x = ''.join(result[1])
    time = x.strip('"')
    time_d = decimal.Decimal(time)
    print(time_d)

    #d = decimal.Decimal((result[0]))
    #print(d)

    #datetime_time = datetime.datetime.fromtimestamp(d)
    #print(datetime_time)

    """
    testing stuff
    """

    #return_message = '{"time": ' + str(log_event['timestamp']) + ',"host": "' + arn  +'","source": "' + filterName +':' + loggrp + '"'
    #return_message = '{"time": "' +  str(datetime_time) + '","host": "' + arn  +'","source": "' + filterName +':' + loggrp + '"'
    # this one works.... return_message = '{"time": ' + str(d) + ',"host": "' + arn  +'","source": "' + filterName +':' + loggrp + '"'
    # more efficient return_message = '{"time": ' + result[0] + ',"host": "' + arn  +'","source": "' + filterName +':' + loggrp + '"'
    #return_message = '{"time": ' + result[0] + ',"host": "' + arn + '","source": "' + source +'"'
    return_message = '{"time": ' + str (time_d) + ',"host": "' + str (host) + '","source": "'+ source +'"'
    return_message = return_message + ',"sourcetype":"' + sourcetype  + '"'
    return_message = return_message + ',"event": ' + json.dumps(log_event['message']) + '}\n'
    print(return_message)
    return return_message + '\n'

def processRecords(records,arn):
    for r in records:
        data = base64.b64decode(r['data'])
        if IS_PY3:
            striodata = io.BytesIO(data)
        else:
            striodata = StringIO.StringIO(data)
        with gzip.GzipFile(fileobj=striodata, mode='r') as f:
            data = json.loads(f.read())

        recId = r['recordId']
        """
        CONTROL_MESSAGE are sent by CWL to check if the subscription is reachable.
        They do not contain actual data.
        """
        if data['messageType'] == 'CONTROL_MESSAGE':
            yield {
                'result': 'Dropped',
                'recordId': recId
            }
        elif data['messageType'] == 'DATA_MESSAGE':
            data = ''.join([transformLogEvent(e,data['owner'],arn,data['logGroup'],data['logStream'],data['subscriptionFilters'][0]) for e in data['logEvents']])
            if IS_PY3:
                data = base64.b64encode(data.encode('utf-8')).decode()
            else:
                data = base64.b64encode(data)
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

    records = list(processRecords(event['records'],streamARN))
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