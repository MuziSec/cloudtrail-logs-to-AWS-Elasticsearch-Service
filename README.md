# cloudtrail-logs-to-AWS-Elasticsearch-Service

This will pull objects from S3 as they are delivered and will post them into your ElasticSearch cluster. It gets its privileges from an IAM role (see ). It gets all its configuration from Lambda environment variables. You should not need to edit the source code to deploy it.

Once you've got CloudTrail reliably inserted into your ElasticSearch cluster, start looking at stuff like [Traildash2](https://github.com/adcreare/traildash2) or AWS [cloudwatch logs subscription consumer](https://github.com/amazon-archives/cloudwatch-logs-subscription-consumer/tree/master/configuration/kibana). Both are very old, but they contain some useful widgets for visualisations.


![CloudTrail Sample Dashboard](https://raw.githubusercontent.com/pacohope/cloudtrail-logs-to-AWS-Elasticsearch-Service/master/cloudtrail-kibana.png)

# Prerequisites

- Access to [AWS Lambda](https://console.aws.amazon.com/lambda/home)
- CloudTrail already set to store logs in an s3 bucket. Don't have that? Follow this [documentation](https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudtrail-logging.html).
- An elasticsearch cluster. Either build it yourself, or [follow the tutorial in the documentation](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-gsg-create-domain.html).

# Installation for CloudTrail

Once you've got CloudTrail logging to S3 and your ElasticSearch cluster accepting input, you're ready to do this work. This will set up an S3 event listener. When an object is put in S3, this code gets called. This code unzips the S3 object and squirts it into ElasticSearch.

## Set Up IAM permissions
You need to create some policies and attach them to a role. That will give your Lambda function the ability to execute. The easiest way to do this is to create a single IAM policy that grants all the permissions you need, and then attach that one policy to the Lambda role. (You could have a few policies—one for elasticsearch, one for S3, one for CloudWatch Logs—and then attach 3 policies to the one role)

### IAM Policy

The IAM policy allows 3 things: Reading your S3 bucket to get cloudtrail, posting records to your ElasticSearch cluster, and CloudWatch Logs for writing any errors or logging.

1. Edit the `lambda-iam-policy.json` file
   1. Add in the bucket name for your bucket.
   2. Add in the domain name you assigned to your ElasticSearch domain.
1. Create an IAM policy, name it something like `CloudTrailESAccess` and set its contents to be the `lambda-iam-policy.json` file.

### Create a Role For your Lambda Function

Create an AWS IAM role.
1. Choose Lambda as the service for the role.
2. Attach the policy you created.

### Prep the Lambda Function

1. Clone this repo
1. On your terminal, install the requests module on the same folder with `pip install requests -t .`
1. Make a zip file that includes the python file and the requests library. From within the repo, run `zip -r lambda-function.zip cloudtrail2ES.py *`

### Create the Lambda Function

These are instructions for doing it by hand in the console. There's also a [cloudtrail2ES.yaml](cloudtrail2ES.yaml) file that contains some CloudFormation.

1. Create a new Lambda Function
2. Choose **Python 3.6** as a runtime.
3. Choose to start with an empty function.
4. Set the handler for the function is `lambda_handler`
5. Set the environment variables:
   * `ES_INDEX` set to something like `cloudtrail`. That will result in ElasticSearch indexes like `cloudtrail-2019-01-19`.
   * `ES_HOST` set to the name of your ElasticSearch endpoint. You can get that from the console or by running `aws es describe-elasticsearch-domain`. The value will look something like: `search-DOMAIN-abcdefgabcdefg.eu-west-1.es.amazonaws.com`. You don't want anything else (no 'https' or / or anything).
6. Test the Lambda function.
   1. Edit the `test-cloudtrail-event.json` file and change the bucket name to be your CloudTrail bucket. Go find a real key ("file name") of a CloudTrail object in your bucket and put that in the `key` parameter.
   1. Invoke the test and set your test event to be this JSON object. Debug any problems.
   1. If the test was successful, you have a few objects in your ElasticSearch cluster now. 
   1. If the test was unsuccessful, go into the CloudWatch Logs of your lambda function and look at the error messages. 

### Launch the Lambda from S3 Events

1. Go to your S3 Bucket in the console.
1. Click on Properties
1. Click on Events
1. Click **+ Add Notification**
1. Name the event
1. For **Events**, select "All object create events"
1. For **Prefix**, enter an appropriate prefix. Probably `AWSLogs/`
1. For **Send to**, select the lambda function you created
1. Click **Save**.

### Seeing it Work

It will take time. CloudTrail logs are delivered every few minutes. The S3 events fire pretty much immediately. Then the records are sent to ElasticSearch.

1. Click on the Kibana link in the ElasticSearch console.
1. Click on the Management gear icon
1. Click on **+ Create Index Pattern**
1. Name the index pattern `cloudtrail-*` (or whatever you used for the `ES_INDEX` value). You should see something helpful like **Your index pattern matches 2 indices**
1. Choose the `@timestamp` field for your timestamp
1. Save the index
1. Click on the **Discover** link at the top left. You should see some CloudTrail records.

### CloudWatch Logs

If you look at your function in the Lambda console, you'll see a tab labeled **Monitoring**. There's a link for its logs on cloudwatch, you can see what the lambda function is doing.

You will want to click on the log group and set its retention time to something. By default, CloudWatch Logs are set to **Never Expire** and that will store every log entry forever. I set mine to 3 days. That's probably generous. I really don't need these logs at all.

# Preloading Events

If, like me, you turned on CloudTrail a long time ago, and now you're just starting to analyse it with ElasticSearch, you might want to import a lot of S3 objects from your CloudTrail bucket. There's a script `loadCloudTrail2ES.py` that will do that. You invoke it something like this:

```
python3 loadCloudTrail2ES.py \
    --bucket MYCLOUDTRAILBUCKET \
    --endpoint MYELASTICSEARCHDOMAIN \
    --region eu-west-1 \
    --prefix AWSLogs/111111111111/CloudTrail/
```

## Other Options
Note that it takes a few other optional arguments that you can use to test before you turn it loose:
* `--limit X` will stop after processing _X_ S3 objects.
* `--dryrun` will cause it to fetch and parse the S3 objects, but it will not `POST` them to ElasticSearch.
* `--index` will name the index something different. By default it names the index `cloudtrail-YYYY-MM-DD`. If you give it `--index foo` on the command line, it will use `foo-YYYY-MM-DD` as the index instead.
* `--profile` will use the `STS::AssumeRole` feature to assume the role for invoking AWS API calls. See [the named profiles documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) for more information on how that works.
* `--prefix` is optional. If you leave it out, it defaults to `AWSLogs/` with the assumption that you probably want to limit yourself to CloudTrail logs, and that's the prefix where they're written by default. If you want no prefix at all, so that the script parses every single object in the bucket, you need to specify `--prefix=/`.

## Notes

The `loadCloudTrail2ES.py` script uses the [bulk upload](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html) API of ElasticSearch. It does not stop to think about whether that would be a good idea. It batches up all the CloudTrail events in the S3 object and sends them to ElasticSearch in a single request. My S3 objects rarely have more than 100 CloudTrail events in them and this always succeeds for me. But if you have a really active account and you have hundreds or thousnds of events in a single S3 object, this might fail.

If you screw up, remember that `curl -X DELETE https://endpoint/cloudtrail-*` is your friend. You can delete ElasticSearch indexes fairly easily.



# Installation for VPCFlow

# Prerequisites

- Access to [AWS Lambda](https://console.aws.amazon.com/lambda/home)
- VPCFlow already set to store logs in an s3 bucket. Don't have that? Follow this [documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html).
- An elasticsearch cluster. Either build it yourself, or [follow the tutorial in the documentation](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-gsg-create-domain.html).

Once you've got VPCFlow logging to S3 and your ElasticSearch cluster accepting input, you're ready to do this work. This will set up an S3 event listener. When an object is put in S3, this code gets called. This code unzips the S3 object and pushes it into ElasticSearch.

## Set Up IAM permissions
You need to create some policies and attach them to a role. That will give your Lambda function the ability to execute. The easiest way to do this is to create a single IAM policy that grants all the permissions you need, and then attach that one policy to the Lambda role. (You could have a few policies—one for elasticsearch, one for S3, one for CloudWatch Logs—and then attach 3 policies to the one role) Note: The IAM permissions will be the exact same as the CloudTrail IAM permissions. The only difference will be the S3 Bucket name, assuming you're using a different bucket. Because of this, we will create a different role, but attach the same policy.

### IAM Policy

The IAM policy allows 3 things: Reading your S3 bucket to get VPCFlow, posting records to your ElasticSearch cluster, and CloudWatch Logs for writing any errors or logging.

1. Edit the `lambda-iam-policy.json` file
   1. Add in the bucket name for your bucket.
   2. Add in the domain name you assigned to your ElasticSearch domain.
1. Create an IAM policy, name it something like `VPCESAccess` and set its contents to be the `lambda-iam-policy.json` file.

### Create a Role For your Lambda Function

Create an AWS IAM role.
1. Choose Lambda as the service for the role.
2. Attach the policy you created.

### Prep the Lambda Function

1. Clone this repo
1. On your terminal, install the requests module on the same folder with `pip install requests -t .`
1. Make a zip file that includes the python file and the requests library. From within the repo, run `zip -r lambda-function.zip ja_vpc2es.py *`

Note: I used `from botocore.vendored import requests`, so the lambda function can just be copy pasted into lambda. This will be deprecated 03/31/20, so this will need to be updated to `requests`. 

### Create the Lambda Function

These are instructions for doing it by hand in the console. There's also a [cloudtrail2ES.yaml](cloudtrail2ES.yaml) file that contains some CloudFormation.

1. Create a new Lambda Function
2. Choose **Python 3.6** as a runtime.
3. Choose to start with an empty function.
4. Set the handler for the function is `lambda_handler`
5. Set the environment variables:
   * `ES_INDEX` set to something like `vpcflow`. That will result in ElasticSearch indexes like `vpcflow-2019-03-20`.
   * `ES_HOST` set to the name of your ElasticSearch endpoint. You can get that from the console or by running `aws es describe-elasticsearch-domain`. The value will look something like: `search-DOMAIN-abcdefgabcdefg.eu-west-1.es.amazonaws.com`. You don't want anything else (no 'https' or / or anything).
6. Test the Lambda function.
   1. Edit the `test-cloudtrail-event.json` file and change the bucket name to be your VPCFlow bucket. Go find a real key ("file name") of a VPCFlow object in your bucket and put that in the `key` parameter. (The same test event can be used, just choose a VPCFlow log rather than CloudTrail)
   1. Invoke the test and set your test event to be this JSON object. Debug any problems.
   1. If the test was successful, you have a few objects in your ElasticSearch cluster now. 
   1. If the test was unsuccessful, go into the CloudWatch Logs of your lambda function and look at the error messages. 

### Launch the Lambda from S3 Events

1. Go to your S3 Bucket in the console.
1. Click on Properties
1. Click on Events
1. Click **+ Add Notification**
1. Name the event
1. For **Events**, select "All object create events"
1. For **Prefix**, enter an appropriate prefix. Probably `AWSLogs/`
1. For **Send to**, select the lambda function you created
1. Click **Save**.

### Seeing it Work

It will take time. VPCFlow logs are delivered every few minutes. The S3 events fire pretty much immediately. Then the records are sent to ElasticSearch.

1. Click on the Kibana link in the ElasticSearch console.
1. Click on the Management gear icon
1. Click on **+ Create Index Pattern**
1. Name the index pattern `vpcflow-*` (or whatever you used for the `ES_INDEX` value). You should see something helpful like **Your index pattern matches 2 indices**
1. Choose the `@timestamp` field for your timestamp
1. Save the index
1. Click on the **Discover** link at the top left. You should see some CloudTrail records.



## Notes

If you screw up, remember that `curl -X DELETE https://endpoint/vpcflow-*` is your friend. You can delete ElasticSearch indexes fairly easily.


# Acknowledgements

You might want to look at [Fernando's blog](https://www.fernandobattistella.com.br/log_processing/2016/03/13/Cloudtrail-S3-Lambda-Elasticsearch.html).

Thanks to [the original](https://github.com/argais/cloudtrail_aws_es.git) and to [pavan3401](https://github.com/pavan3401/cloudtrail-logs-to-AWS-Elasticsearch-Service) for forking and improving some.

Thanks to pocohope for his updates to pava3401's work. I hope my addition of VPCFlow logs can help someone out! 
