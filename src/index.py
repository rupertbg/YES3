import yaml
import json
import boto3
from botocore.exceptions import ClientError

sts = boto3.client('sts')
s3 = boto3.client('s3')
s3_resource = boto3.resource('s3')

def load_policy():
    with open('policy.yml', 'r') as policy_file:
        policy = yaml.safe_load(policy_file)
    policy_file.close()
    return policy

def process_bucket_to_policy(policy, bucket_name):
    result = {}
    if 'PublicAccess' in policy:
        result['public'] = process_public_access(policy, bucket_name)
    return result

def get_public_config_from_policy(policy):
    allow = {
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False
    }
    block = {
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }
    if 'PublicAccess' in policy and 'Configuration' in policy['PublicAccess']:
        if 'Allow' in policy['PublicAccess']['Configuration']:
            allow = policy['PublicAccess']['Configuration']['Allow']
        if 'Block' in policy['PublicAccess']['Configuration']:
            block = policy['PublicAccess']['Configuration']['Block']
    return allow, block

def get_bucket_access_rules(bucket):
    try:
        resp = s3.get_public_access_block(
            Bucket=bucket
        )
        if resp and 'PublicAccessBlockConfiguration' in resp:
            return resp['PublicAccessBlockConfiguration']
    except ClientError as e:
        print('Bucket "{0}": {1}'.format(bucket, e))
    return None

def put_bucket_access_rules(bucket, rules):
    current_config = get_bucket_access_rules(bucket)
    if current_config == None or len(current_config.items() - rules.items()):
        print('WARNING: Remediating bucket "{0}" as it differs from policy'.format(bucket))
        try:
            s3.put_public_access_block(
                PublicAccessBlockConfiguration=rules,
                Bucket=bucket
            )
        except ClientError as e:
            print('Error processing "{0}": {1}'.format(bucket, e))


def get_buckets_from_policy(policy):
    buckets = []
    if 'PublicAccess' in policy and 'Buckets' in policy['PublicAccess']:
        for bucket in policy['PublicAccess']['Buckets']:
            if isinstance(bucket, dict):
                if 'Name' in bucket:
                    buckets.append(bucket)
            elif isinstance(bucket, str):
                buckets.append({ 'Name': bucket })
    return buckets

def get_bucket_from_policy(policy, bucket_name):
    buckets = get_buckets_from_policy(policy)
    return next((bucket for bucket in buckets if 'Name' in bucket and bucket['Name'] == bucket_name), None)

def process_public_access(policy, bucket):
    allow, block = get_public_config_from_policy(policy)
    policy_bucket = get_bucket_from_policy(policy, bucket)
    if policy_bucket:
        if 'Configuration' in policy_bucket:
            put_bucket_access_rules(bucket, policy_bucket['Configuration'])
        else:
            put_bucket_access_rules(bucket, allow)
        return True
    if 'Block' in policy['PublicAccess'] and policy['PublicAccess']['Block']:
        put_bucket_access_rules(bucket, block)
        return False
    current_config = get_bucket_access_rules(bucket)
    if len(current_config.items() - allow.items()) or len(current_config.items() - block.items()):
        return 'non-compliant'

def scan(policy, buckets):
    results = {}
    if len(buckets) == 0:
        buckets = [bucket.name for bucket in s3_resource.buckets.all()]
        print('Scanning all buckets')
    else:
        print('Scanning changed buckets: {0}'.format(buckets))

    for bucket in buckets:
        results[bucket] = process_bucket_to_policy(policy, bucket)

    return json.dumps({
        'result': 'SUCCESS',
        'data': results
    })

def is_self_invocation(detail):
    identity = sts.get_caller_identity()
    if 'userIdentity' in detail:
        if 'arn' in detail['userIdentity'] and 'Arn' in identity:
            if identity['Arn'] == detail['userIdentity']['arn']:
                return True
    return False

def handler(event, context):
    policy = load_policy()
    buckets = []

    if 'detail' in event:
        detail = event['detail']
        if is_self_invocation(detail):
            return json.dumps({
                'result': 'FAILURE',
                'data': 'Self invocation via CloudWatch Event'
            })
        if 'requestParameters' in detail and 'bucketName' in detail['requestParameters']:
            buckets.append(detail['requestParameters']['bucketName'])
        if 'resources' in event['detail']:
            resources = detail['resources']
            buckets = buckets + [bucket['ARN'].split('arn:aws:s3:::')[1] for bucket in resources if bucket['type'] == 'AWS::S3::Bucket']

    return scan(policy, buckets)
