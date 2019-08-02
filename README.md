# YES3 - Flexible S3 Public Access Control Automation
Do you have _intentionally public_ S3 Buckets? Do these change over time? This Lambda function will continuously update S3 Public Access settings to comply to a policy given to it via this repo.

Constraining other IAM Users and Roles from accessing these settings will mean greatly reduced risk of misconfiguration of buckets, whilst retaining the ability to have public buckets where it makes sense.

## Deployment
Included is a CodePipeline defined in CloudFormation. This bundles up the Lambda and it's dependancies via CodeBuild, and uploads the resulting zip to S3 where it is then referenced in a CloudFormation deployment step for the Lambda itself. The pipeline updates itself based on the `pipeline.yml` included in the repo.

### First time setup:
1. Make a Secret in Secrets Manager called 'Github' and place two values in it:
    - PersonalAccessToken: A Personal Access Token from Github
    - WebhookSecret: A random string for adding access control to the CodePipeline webhook
2. Deploy the `pipeline.yml` via CloudFormation
3. For automatic pipeline execution on push events, configure the Webhook URL that is exported from the resulting stack in your Github repo's Webhook settings.

## Policy Definition
The `policy.yml` file located in `src` is parsed by the Lambda Function. If you omit the `PublicAccess.Configuration` objects, they will default to Allow being fully open and Block being fully closed. Setting `PublicAccess.Block` to true and omiting the list of buckets will set `PublicAccess.Configuration.Block` on all buckets.
```yaml
PublicAccess: # This object governs S3 Public Access Blocks (https://aws.amazon.com/blogs/aws/amazon-s3-block-public-access-another-layer-of-protection-for-your-accounts-and-buckets/)
  Block: true # Setting this to true will enable active blocking of non-whitelisted buckets
  Configuration: # These four setting map directly to the parameters available for PutPublicAccessBlock.
    Allow: # These are the settings enforced when a bucket appears in the whitelist below.
      BlockPublicAcls: true
      IgnorePublicAcls: true
      BlockPublicPolicy: false
      RestrictPublicBuckets: false
    Block: # These are the settings enforced when a bucket doesn't appear in the whitelist below.
      BlockPublicAcls: true
      IgnorePublicAcls: true
      BlockPublicPolicy: true
      RestrictPublicBuckets: true
  Buckets: # Bucket names in this list will be allowed to be public based on the configuration set above. All other buckets will have all configurations above set to False, blocking all public access.
    - testing-bucket-123456
```

### Examples
Block all public configurations
```yaml
PublicAccess:
  Block: true
```

Ensure public configurations are allowed on test-bucket-123456
```yaml
PublicAccess:
  Buckets:
    - test-bucket-123456
```

_Only_ allow public configurations on test-bucket-123456
```yaml
PublicAccess:
  Block: true
  Buckets:
    - test-bucket-123456
```

Block all buckets with a custom ruleset. This one allows public policy but not ACLs
```yaml
PublicAccess:
  Block: true
  Configuration:
    Block:
      BlockPublicAcls: true
      IgnorePublicAcls: true
      BlockPublicPolicy: false
      RestrictPublicBuckets: false
```

## Files
```
| README.md
| lambda.yml - Lambda deployment written in CloudFormation
| pipeline.yml - CodePipeline definition written in CloudFormation
| src
| | requirements.txt - Pip requirements file
| | index.py - Lambda handler
| | policy.yml - Policy file for defining public buckets and settings
```
