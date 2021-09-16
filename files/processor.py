import base64
import boto3
import json
import sys
import gzip
import re
import datetime
import time

IS_PY3 = sys.version_info[0] == 3

if IS_PY3:
    import io
else:
    import StringIO


ssm_client = boto3.client('ssm')


def transformLogEvent(log_event, source, owner, config, streamName):
    return_message = "EVENT_NOT_FOUND"
    print("  Event: ", log_event)
    print(" Source: ", source)
    print("Account: ", owner)
    print(" Config: ", config)
    event = log_event['message']

    for pattern in config['patterns']:
        print("Searching for ", streamName, " in config ", pattern['streamname'])
        result = re.findall(streamName, pattern['streamname'])

        if result:
            date_result = re.findall(pattern['date_regex'], event)
            print("Searching for ", pattern['date_regex'], " in ", event)

            if date_result:
                print("Found Date Result: ", date_result)
                x = event.split()
                host_pos = int(pattern['host_pos'])
                host = x[host_pos]
                print("Found Host: ", host)

                if pattern['date_time'] == 'standard':
                    print("Using ", pattern['date_time'])
                    x = ''.join(date_result[0])
                    log_time = x.strip('"')
                    print("Log Time: ", log_time)

                    try:
                        if pattern['fix_year']:
                            print("Fixing year...")
                            now = str(datetime.datetime.now().year)
                            full_time = now + ' ' + log_time
                            print("Full Time: ", full_time)
                            log_time = full_time
                    except KeyError as e:
                        pass

                    utc_time = datetime.datetime.strptime(log_time, pattern['date_format'])
                    print("UTC Time: ", utc_time)
                    epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
                    if pattern['utc_offset']:
                        print("Fixing UTC Offset... ")
                        utc_offset = time.localtime().tm_gmtoff
                        epoch_time = epoch_time - utc_offset
                    print("Epoch Time: ", epoch_time)
                else:
                    epoch_time = date_result[0]
                    print("Epoch Time: ", epoch_time)

                return_message = '{"time": ' + str(epoch_time) + ',"host": "' + str (host) + '","source": "'+ pattern['source'] +'"'
                return_message = return_message + ',"sourcetype":"' + pattern['sourcetype'] + '"'
                return_message = return_message + ',"index":"' + pattern['index'] + '"'
                # return_message = return_message + ',"account":"' + owner + '"'
                return_message = return_message + ',"event": {"message": ' + json.dumps(log_event['message']) + ', "account": "' + owner + '"}}\n'
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
    return {"records": records}

    # projectedSize = 0
    # dataByRecordId = {rec['recordId']: createReingestionRecord(isSas, rec) for rec in event['records']}
    # putRecordBatches = []
    # recordsToReingest = []
    # totalRecordsToBeReingested = 0
    #
    # for idx, rec in enumerate(records):
    #     if rec['result'] != 'Ok':
    #         continue
    #     projectedSize += len(rec['data']) + len(rec['recordId'])
    #     # 6000000 instead of 6291456 to leave ample headroom for the stuff we didn't account for
    #     if projectedSize > 6000000:
    #         totalRecordsToBeReingested += 1
    #         recordsToReingest.append(
    #             getReingestionRecord(isSas, dataByRecordId[rec['recordId']])
    #         )
    #         records[idx]['result'] = 'Dropped'
    #         del(records[idx]['data'])
    #
    #     # split out the record batches into multiple groups, 500 records at max per group
    #     if len(recordsToReingest) == 500:
    #         putRecordBatches.append(recordsToReingest)
    #         recordsToReingest = []
    #
    # if len(recordsToReingest) > 0:
    #     # add the last batch
    #     putRecordBatches.append(recordsToReingest)
    #
    # # iterate and call putRecordBatch for each group
    # recordsReingestedSoFar = 0
    # if len(putRecordBatches) > 0:
    #     kinesis_client = boto3.client('kinesis', region_name=region) if isSas else boto3.client('firehose', region_name=region)
    #     for recordBatch in putRecordBatches:
    #         if isSas:
    #             putRecordsToKinesisStream(streamName, recordBatch, kinesis_client, attemptsMade=0, maxAttempts=20)
    #         else:
    #             putRecordsToFirehoseStream(streamName, recordBatch, kinesis_client, attemptsMade=0, maxAttempts=20)
    #         recordsReingestedSoFar += len(recordBatch)
    #         print('Reingested %d/%d records out of %d' % (recordsReingestedSoFar, totalRecordsToBeReingested, len(event['records'])))
    # else:
    #     print('No records to be reingested')

    # return {"records": records}


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
