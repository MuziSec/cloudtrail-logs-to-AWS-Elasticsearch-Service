"""
Lambda function that is triggered by S3 All Objects Create Event for CloudTrail log files. Code will download the file from S3, unzip it, filter out designated events and insert JSON contents into ES.

Signed URL code taken from AWS docs and adapted for this script.
For additional information on Signing HTTP Requests for ES: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-request-signing.html#es-request-signing-python
"""

import json
import gzip
from botocore.vendored import requests
import datetime
import hashlib
import hmac
import boto3
import os
import tempfile
from decimal import Decimal
from datetime import datetime as dt

##########################################################################
# Variables to be set in Lambda Environment Variables

# No HTTPS nor trailing slash, just full hostname of ElasticSearch Endpoint
host = os.environ.get('ES_HOST')
region = os.environ.get('AWS_REGION')
service= 'es'
method = 'POST'
content_type = 'application/json'

# Set the index name for ElasticSearch. If indexname is set to 'foo', then it will write to an index foo-YYYY-MM-DD
# Index name is set to 'vpcflow' by default
indexname = os.environ.get('ES_INDEX')
if (indexname == None):
    indexname = "vpcflow"

access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
session_token = os.environ.get('AWS_SESSION_TOKEN')

# functions used in the aws signed url
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

# Define S3 boto client
s3 = boto3.client('s3')

# Main Function, Started by Lambda
def lambda_handler(event, context):
    # Attribute bucket and file name/path to variables
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    if(bucket == None or key == None):
        return

    # Temporary location to save file downloaded from S3
    s3obj = tempfile.NamedTemporaryFile(mode='w+b',delete=False)
 
    # Download file to temp file
    s3.download_file(bucket, key, s3obj.name)

    with gzip.open(s3obj.name, 'rb') as f:
        if ("interface-id" not in f.readline().decode()):
            print("Not VPCFlow, exiting.")
            # return 
        eventcount = 1
        for line in f:
            event_array = line.split()
            event_dict = {}
            # Parse array to dict to prepare for JSON conversion
            event_dict['version'] = event_array[0].decode()
            event_dict['account-id'] = event_array[1].decode()
            event_dict['interface-id'] = event_array[2].decode()
            event_dict['srcaddr'] = event_array[3].decode()
            event_dict['dstaddr'] = event_array[4].decode()
            event_dict['srcport'] = event_array[5].decode()
            event_dict['dstport'] = event_array[6].decode()
            event_dict['protocol'] = event_array[7].decode()
            event_dict['packets'] = event_array[8].decode()
            event_dict['bytes'] = event_array[9].decode()
            event_dict['start'] = event_array[10].decode()
            event_dict['end'] = event_array[11].decode()
            event_dict['action'] = event_array[12].decode()
            event_dict['log-status'] = event_array[13].decode()
            
            # Prepare JSON to send to ES
            data = json.dumps(event_dict).encode('utf-8')
            print(data)
            
            event_date = dt.today().strftime('%Y-%m-%d')
            
            canonical_uri = '/' + indexname + '-' + event_date + '/_doc'
            # url endpoint for our ES cluster
            url = 'https://' + host + canonical_uri
            print( "Event {} url : {}\n".format(eventcount, url))
    
            # aws signed url stuff - for comments on this check their example page linked on top comment
            t = datetime.datetime.utcnow()
            amz_date = t.strftime('%Y%m%dT%H%M%SZ')
            date_stamp = t.strftime('%Y%m%d')
            canonical_querystring = ''
            canonical_headers = 'content-type:' + content_type + '\n' + \
                                'host:' + host + '\n' + \
                                'x-amz-date:' + amz_date + '\n'
            signed_headers = 'content-type;host;x-amz-date'
            payload_hash = hashlib.sha256(data).hexdigest()
            canonical_request = method + '\n' + \
                                canonical_uri + '\n' + \
                                canonical_querystring + '\n' + \
                                canonical_headers + '\n' + \
                                signed_headers + '\n' + \
                                payload_hash
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
            string_to_sign = algorithm + '\n' + \
                             amz_date + '\n' + \
                             credential_scope + '\n' + \
                             hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
            signing_key = get_signature_key(secret_key, date_stamp, region, service)
            signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
            authorization_header = algorithm + ' ' + \
                                   'Credential=' + access_key + '/' + credential_scope + ', ' + \
                                   'SignedHeaders=' + signed_headers + ', ' + \
                                   'Signature=' + signature
            headers = {'Content-Type':content_type,
                       'X-Amz-Date':amz_date,
                       'Authorization':authorization_header, 'X-Amz-Security-Token': session_token}
            
            # sends the json to elasticsearch
            req = requests.post(url, data=data, headers=headers)
            print( "Attempt 0 status code: {}".format(req.status_code))
            print( "response:\n---\n{}\n---\n".format( req.text ))
            
            retry_counter = 1

            """
            if we fail for some reason we will retry 3 times
            you will most likely have errors if you're copying a huge ammount of logs from an old bucket
            to your new one.
    
            For normal usage you shouldnt have to worry about this.
            I got it in production with 90 aws accounts pointing to the same bucket,
            and a pair of m3.mediums on the ES cluster, with 0 errors.
    
            I dont raise an exception on errors to not miss all the other entries in the file, or risk repeating any
            inserts done before the error.
            """
            # if our status code is not successfull, and our retry counter is less than 4
            while (req.status_code != 201) and (retry_counter < 4):
                print( "Got code {}. Retrying {} of 3".format( req.status_code, retry_counter) )
    
                # send the data to ES again
                req = requests.post(url, data=data, headers=headers)
    
                print( "status code: {}".format(req.status_code))
                retry_counter += 1
            eventcount +=1
        
    s3obj.close()
    os.unlink(s3obj.name)
    
