import base64
import json
import gzip
import os
import sys
import re
import datetime
import decimal

pattern = '(\w{3}\s{1,2}\d+ \d{2}:\d{2}:\d{2}) |(\w{2}-\d+-\d+-\d+-\d+)'

sourcetype = "linux:messages"
source = "var/log/messages"

test_string = "Aug 25 09:50:01 ip-10-4-0-205 systemd: Created slice User Slice of root."

result = re.findall(pattern, test_string)
# print(test_string)

print(result)

x = result[0]
x = ''.join(result[0])
time = x.strip('"')
# print(time)

# x = result.split[1]
x = ''.join(result[1])
host = x.strip('"')
# print(host)

# need to add the year to the timestamp so we can convert to an epoch....

now = str(datetime.datetime.now().year)

full_time = now + ' ' + time
# print(full_time)

# utc_time = datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%f")
utc_time = datetime.datetime.strptime(full_time, "%Y %b %d %H:%M:%S")
# print(utc_time)

epoch_time = (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()
print(epoch_time)
# return_message = '{"time": ' + str(time_d) + ',"host": "' + str(host) + '","source": "' + source + '"'
# return_message = return_message + ',"sourcetype":"' + sourcetype + '"'
# return_message = return_message + json.dumps(test_string) + '}\n'
# print(return_message)
