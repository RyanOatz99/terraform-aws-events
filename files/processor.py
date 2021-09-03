import base64
import boto3
import json
import sys
import gzip
import re
import datetime

IS_PY3 = sys.version_info[0] == 3

if IS_PY3:
    import io
else:
    import StringIO


ssm_client = boto3.client('ssm')

def transformLogEvent(log_event, source, owner, config, streamName):
    return_message = "EVENT_NOT_FOUND"
    print(" Event: ",log_event)
    print("Source: ",source)
    print(" Owner: ",owner)
    print("Config: ",config)
    event = log_event['message']
    print("LOG_EVENT: ", event)
    print("EVENT_STREAMNAME: ", streamName)

    for pattern in config['patterns']:
        print("LOOKING FOR ", streamName , " IN " ,pattern['streamname'])
        result = re.findall(streamName, pattern['streamname'])
        if result:
            print("PATTERN STREAMNAME: ", pattern['streamname'])
            print("RESULT: ", result)
            date_result = re.findall(pattern['date_regex'], event)
            print("LOOKING FOR ", pattern['date_regex'], " IN " , event)
            if date_result:
                print("DATE_RESULT: ", date_result)
                x = ''.join(date_result[0])
                log_time = x.strip('"')

                x = event.split()
                host = x[1]

                utc_time = datetime.datetime.strptime(log_time, pattern['date_format'])
                epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()

                return_message = '{"time": ' + str(epoch_time) + ',"host": "' + str (host) + '","source": "'+ pattern['source'] +'"'
                return_message = return_message + ',"sourcetype":"' + pattern['sourcetype'] + '"'
                return_message = return_message + ',"index":"' + pattern['index'] + '"'
                return_message = return_message + ',"event": ' + json.dumps(log_event['message']) + '}\n'
                print(return_message)

        return return_message + '\n'


def processRecords(records, config, streamName):
    for r in records:
        data = base64.b64decode(r['data'])
        if IS_PY3:
            iodata = io.BytesIO(data)
        else:
            iodata = StringIO.StringIO(data)
        with gzip.GzipFile(fileobj=iodata, mode='r') as f:
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
            # source = data['logGroup'] + ":" + data['logStream']
            source = data['logGroup']
            data = ''.join([transformLogEvent(e, source, data['owner'], config, streamName) for e in data['logEvents']])
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


def createReingestionRecord(isSas, originalRecord):
    if isSas:
        return {'data': base64.b64decode(originalRecord['data']), 'partitionKey': originalRecord['kinesisRecordMetadata']['partitionKey']}
    else:
        return {'data': base64.b64decode(originalRecord['data'])}


def handler(event, context):
    config = json.loads(ssm_client.get_parameter(Name='/pm/processor/config', WithDecryption=True)['Parameter']['Value'])
    # print("EVENT:")
    # print(event)
    # print("CONTEXT:")
    # print(context)
    print()
    isSas = 'sourceKinesisStreamArn' in event
    streamARN = event['sourceKinesisStreamArn'] if isSas else event['deliveryStreamArn']
    region = streamARN.split(':')[3]
    streamName = streamARN.split('/')[1]
    records = list(processRecords(event['records'], config, streamName))
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
        kinesis_client = boto3.client('kinesis', region_name=region) if isSas else boto3.client('firehose', region_name=region)
        for recordBatch in putRecordBatches:
            if isSas:
                putRecordsToKinesisStream(streamName, recordBatch, kinesis_client, attemptsMade=0, maxAttempts=20)
            else:
                putRecordsToFirehoseStream(streamName, recordBatch, kinesis_client, attemptsMade=0, maxAttempts=20)
            recordsReingestedSoFar += len(recordBatch)
            print('Reingested %d/%d records out of %d' % (recordsReingestedSoFar, totalRecordsToBeReingested, len(event['records'])))
    else:
        print('No records to be reingested')

    return {"records": records}

    # json_param = json.loads(param['Parameter']['Value'])

    # pattern_date_regex = []

    # for pattern in config['patterns']:
    #     pattern_date_regex.append(pattern['date_regex'])

    # print('Available date regex:')
    # print(pattern_date_regex)

    # for date_regex in pattern['date_regex']:
    #     print(date_regex)

    # for pattern in config['patterns']:
    #     processPattern(pattern)
