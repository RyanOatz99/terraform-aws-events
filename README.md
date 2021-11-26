Description
=
This module is designed to enable various Event Rules, and also deploys the infrastructure to support sending these Events on a per-account basis to Splunk in GCP.

Usage
=

modules_[AWS_ACCOUNT_NAME].tf
-

    module "events_[CUSTOM_NAME]" {
        providers = {
        aws = aws.[CUSTOM_PROVIDER_ALIAS]
    }
    source  = "./events/"
    version = "revision number"
    name    = "[AWS_ACCOUNT_NAME]-events"
    index   = "Splunk index name"

    dev_account = "true"

    # Enable whole-service Rules
    securityhub_rules = "true"
    guardduty_rules   = "true"
    cloudtrail_rules  = "true"
    
    # Enable CloudWatch Event per-service Rules
    autoscaling_rules                 = "true"
    batch_rules                       = "true"
    cloudwatch_scheduled_events_rules = "true"
    codebuild_rules                   = "true"
    codecommit_rules                  = "true"
    codedeploy_rules                  = "true"
    codepipeline_rules                = "true"
    config_rules                      = "true"
    dlm_rules                         = "true"
    ec2_rules                         = "true"
    ecs_rules                         = "true"
    emr_rules                         = "true"
    glue_rules                        = "true"
    health_rules                      = "true"
    kms_rules                         = "true"
    macie_rules                       = "true"
    mediaconvert_rules                = "true"
    medialive_rules                   = "true"
    mediastore_rules                  = "true"
    opsworks_rules                    = "true"
    signer_rules                      = "true"
    sms_rules                         = "true"
    ssm_rules                         = "true"
    storagegateway_rules              = "true"
    transcribe_rules                  = "true"
    workspaces_rules                  = "true"
    
    # Splunk config
    splunk_endpoint            = var.splunk_endpoint
    cloudwatchevents_hec_token = var.cloudwatchevents_hec_token
    securityhub_hec_token      = var.securityhub_hec_token
    guardduty_hec_token        = var.guardduty_hec_token
    cloudtrail_hec_token       = var.cloudtrail_hec_token
    cloudwatchlogs_hec_token   = var.cloudwatchlogs_hec_token
    linux_audit_cloudwatchlogs_hec_token    = var.linux_audit_cloudwatchlogs_hec_token
    linux_syslog_cloudwatchlogs_hec_token   = var.linux_syslog_cloudwatchlogs_hec_token
    metadataserver_cloudwatchlogs_hec_token = var.metadataserver_cloudwatchlogs_hec_token
    linux_secure_cloudwatchlogs_hec_token   = var.linux_secure_cloudwatchlogs_hec_token
    storagegw_cloudwatchlogs_hec_token      = var.storagegw_cloudwatchlogs_hec_token
    ssm_cloudwatchlogs_hec_token            = var.ssm_cloudwatchlogs_hec_token
    sasworkspace_cloudwatchlogs_hec_token   = var.sasworkspace_cloudwatchlogs_hec_token

    #CloudWatch Log Groups
    cloudwatch_logs_to_ship = []

    #Linux Audit Cloudwatch Log Groups
    linux_audit_cloudwatch_logs_to_ship = []

    #Linux Syslog Cloudwatch Log Groups
    linux_syslog_cloudwatch_logs_to_ship = []

    #Linux Secure Cloudwatch log Groups
    linux_secure_cloudwatch_logs_to_ship = []

    #Storage Gateway Cloudwatch Log Group
    storagegw_cloudwatch_logs_to_ship = []

    #metadataserver Cloudwatch Log Group
    metadataserver_cloudwatch_logs_to_ship = []

    #sasworkspace Cloudwatch Log Group
    sasworkspace_cloudwatch_logs_to_ship = []

    #ssm Cloudwatch Log Group
    ssm_cloudwatch_logs_to_ship = []
    

   

In addition, usage of the module may require:
* A custom provider with an alias
        
        provider "aws" {
            alias   = "[CUSTOM_PROVIDER_ALIAS]"
            region  = "[REGION]"
            profile = "[AWS_CREDENTIALS_PROFILE_NAME]"
        }
  
  * A variables.tf for seeding the module
  
          variable "vpcflowlogs_hec_token" {
              description = "The HEC Token for VPCFlowLogs"
              default     = "[VPC_FLOW_LOGS_HEC_TOKEN]"
              type        = string
          }
        
          variable "cloudtrail_hec_token" {
              description = "The HEC Token for CloudTrail"
              default     = "[CLOUDTRAIL_HEC_TOKEN]"
              type        = string
          }
        
          variable "cloudwatchevents_hec_token" {
              description = "The HEC Token for CloudWatch Events"
              default     = "[CLOUDWATCH_EVENTS_HEC_TOKEN]"
              type        = string
          }
        
          variable "guardduty_hec_token" {
              description = "The HEC Token for GuardDuty"
              default     = "[GUARD_DUTY_HEC_TOKEN]"
              type        = string
          }
        
          variable "securityhub_hec_token" {
              description = "The HEC Token for VPCFlowLogs"
              default     = "[VPC_FLOWLOGS_HEC_TOKEN]"
              type        = string
          }

          variable "cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }

          variable "metadataserver_cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[METADATASERVER_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }

          variable "linux_audit_cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[LINUX_AUDIT_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }

          variable "linux_syslog_cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[LINUX_SYSLOG_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }

          variable "storagegw_cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[STORAGEGW_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }  
          
          variable "sasworkspace_cloudwatchlogs_hec_token" {
              description = "sasworkspace CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[SASWORKSPACE_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }  

          variable "linux_secure_cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[LINUX_SECURE_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }        

          variable "ssm_cloudwatchlogs_hec_token" {
              description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[SSM_CLOUDWATCH_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }        
          
          variable "linux_messages_cloudwatchlogs_hec_token" {
              description = "Linux Messages CloudWatchLogs HEC Token for use with Splunk Endpoint"
              default     = "[LINUX_MESSAGES_LOG_GROUP_HEC_TOKEN]"
              type        = string
          }     

          variable "splunk_endpoint" {
              description = "The Splunk Endpoint URI"
              default     = "[SPUNK_ENDPOINT_HTTPS_ADDRESS]"
              type        = string
          }





Inputs:
=

name
-
    The name of the Event
    default = ""
    type = string


cloudwatchevents_hec_token
-
    CloudWatch Events HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

cloudtrail_hec_token
-
    CloudTrail HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

dev_account
-
    Set to "true" if target is a development Account
    default     = "false"
    type        = string

guardduty_hec_token
-
    GuardDuty HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

securityhub_hec_token
-
    SecurityHub HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

metadataserver_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

linux_audit_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

linux_syslog_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

linux_secure_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

linux_storagegw_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

ssm_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

linux_messages_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

sasworkspace_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint
    default     = ""
    type        = string

splunk_endpoint
-
    Endpoint address for Splunk
    default     = ""
    type        = string

guardduty_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

securityhub_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

cloudtrail_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

autoscaling_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

batch_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

cloudwatch_scheduled_events_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

codebuild_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

codecommit_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

codedeploy_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

codepipeline_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

config_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

dlm_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

ec2_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

ecs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

emr_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

glue_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

health_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

kms_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

macie_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

mediaconvert_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

medialive_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

mediastore_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

opsworks_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

signer_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

sms_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

ssm_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

storagegateway_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

transcribe_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

workspaces_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

linux_audit_cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

linux_messages_cloudwatch_logs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

metadataserver_cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

storagegw_cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

linux_secure_cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

ssm_cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

sasworkspace_cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

cloudwatchlogs_rules
-
    True if the resource Rules should be enabled.
    default = "false"
    type = string

CloudWatch Log Group Variables
-
    variable "cloudwatch_logs_to_ship" {
    description = "CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }

VPC Flow Logs Variables
-
    variable "vpcid_to_ship" {
    description = "VPCID flow Logs "
    default     = []
    type        = list(string)
    }

    variable "vpcflowlogs_rules" {
    description = "True if the cloudwatchlogs Rules should be enabled."
    default     = "false"
    type        = string
    }

    variable "vpcflowlogs_cloudwatch_log_group_retention_in_days" {
    description = "flow log CloudWatch Log Group retention period"
    default     = "7"
    type        = string
    }

    variable "vpcflowlogs_cloudwatch_log_group_name" {
    description = "CloudWatch Log Group VPC Flow Log Name"
    default     = "vpcflowlogs"
    type        = string
    }

    variable "vpcflowlogs_subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id}" // nothing is being filtered
    }

CloudWatch Syslog Log Group Variables
-
    variable "linux_syslog_cloudwatch_logs_to_ship" {
    description = "Linux Syslog CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }

Linux Audit CloudWatch Log Group Variables
-
    variable "linux_audit_cloudwatch_logs_to_ship" {
    description = "CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }

Metadataserver CloudWatch Log Group Variables
-
    variable "metadataserver_cloudwatch_logs_to_ship" {
    description = "CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }

CloudWatch Storage Gateway Log Group Variables
-
    variable "storagegw_cloudwatch_logs_to_ship" {
    description = "Storage Gateway CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }


CloudWatch linux secure Log Group Variables
-
    variable "linux_secure_cloudwatch_logs_to_ship" {
    description = "Linux Secure CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }


CloudWatch SSM Log Group Variables
-
    variable "ssm_cloudwatch_logs_to_ship" {
    description = "SSM CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }

CloudWatch Linux Messages Log Group Variables
-
    variable "linux_messages_cloudwatch_logs_to_ship" {
    description = "linux messages CloudWatch Log Groups"
    default     = []
    type        = list(string)
    }
  
    variable "subscription_filter_pattern" {
    description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
    default     = "" # nothing is being filtered
    }

    variable "cloudwatch_log_filter_name" {
    description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
    default     = "KinesisSubscriptionFilter"
    }

    variable "log_stream_name" {
    description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
    default     = "SplunkDelivery"
    }

