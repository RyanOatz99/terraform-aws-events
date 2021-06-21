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
    source = "./events/"
    name   = "[AWS_ACCOUNT_NAME]-events"
    
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

    #CloudWatch Log Groups
    cloudwatch_logs_to_ship = []
    }

    #Linux Audit Cloudwatch Log Groups
    linux_audit_cloudwatch_logs_to_ship = []
    }

    #Linux Syslog Cloudwatch Log Groups
    linux_syslog_cloudwatch_logs_to_ship = []
    }

    #metadataserver Cloudwatch Log Groups
    metadataserver_cloudwatch_logs_to_ship = []
    }

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

          variable "splunk_endpoint" {
            description = "The Splunk Endpoint URI"
            default     = "[SPUNK_ENDPOINT_HTTPS_ADDRESS]"
            type        = string
        }





Inputs:
=

name
-
    The name of the Event<br>
    default = ""<br>
    type = string


cloudwatchevents_hec_token
-
    CloudWatch Events HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

cloudtrail_hec_token
-
    CloudTrail HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

guardduty_hec_token
-
    GuardDuty HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

securityhub_hec_token
-
    SecurityHub HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

metadataserver_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

linux_audit_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

linux_syslog_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

linux_secure_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

linux_storagegw_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

ssm_cloudwatchlogs_hec_token
-
    CloudWatch Log Group HEC Token for use with Splunk Endpoint<br>
    default     = ""<br>
    type        = string

splunk_endpoint
-
    Endpoint address for Splunk<br>
    default     = ""<br>
    type        = string<br>

guardduty_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

securityhub_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

cloudtrail_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

autoscaling_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

batch_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

cloudwatch_scheduled_events_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

codebuild_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

codecommit_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

codedeploy_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

codepipeline_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

config_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

dlm_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

ec2_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

ecs_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

emr_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

glue_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

health_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

kms_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

macie_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

mediaconvert_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

medialive_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

mediastore_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

opsworks_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

signer_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

sms_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

ssm_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

storagegateway_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

transcribe_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
    type = string

workspaces_rules
-
    True if the resource Rules should be enabled.<br>
    default = "false"<br>
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

CloudWatch linux secure Log Group Variables
-
    variable "linux_secure_cloudwatch_logs_to_ship" {
    description = "Linux Secure CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }

CloudWatch SSM Log Group Variables
-
    variable "ssm_cloudwatch_logs_to_ship" {
    description = "SSM CloudWatch Log Groups"
    default = ["",""]
    type = list(string)
    }