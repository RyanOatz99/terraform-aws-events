variable "name" {
  description = "The name of the Event"
  default     = ""
  type        = string
}

variable "index" {
  description = "The index in Splunk to send logs to"
  default     = ""
  type        = string
}

variable "host" {
  description = "An optional host variable for when log file has no host entry"
  default     = "localhost"
  type        = string
}

variable "guardduty_rules" {
  description = "True if the GuardDuty Rules should be enabled."
  default     = "false"
  type        = string
}

variable "securityhub_rules" {
  description = "True if the Security Hub Rules should be enabled."
  default     = "false"
  type        = string
}

variable "cloudtrail_rules" {
  description = "True if the CloudTrail Rules should be enabled."
  default     = "false"
  type        = string
}

variable "cloudwatch_events_rules" {
  description = "True if the CW Scheduled Events Rules should be enabled."
  default     = "false"
  type        = string
}

variable "default_processing_lambda" {
  description = "True if the default Lambda Rules should be enabled."
  default     = "true"
  type        = string
}

variable "autoscaling_rules" {
  description = "True if the AutoScaling CW Rules should be enabled."
  default     = "false"
  type        = string
}

variable "batch_rules" {
  description = "True if the AutoScaling CW Rules should be enabled."
  default     = "false"
  type        = string
}

variable "cloudwatch_scheduled_events_rules" {
  description = "True if the CW Scheduled Events Rules should be enabled."
  default     = "false"
  type        = string
}

variable "codebuild_rules" {
  description = "True if the CodeBuild Rules should be enabled."
  default     = "false"
  type        = string
}

variable "codecommit_rules" {
  description = "True if the CodeCommit Rules should be enabled."
  default     = "false"
  type        = string
}

variable "codedeploy_rules" {
  description = "True if the CodeDeploy Rules should be enabled."
  default     = "false"
  type        = string
}

variable "codepipeline_rules" {
  description = "True if the CodePipeline Rules should be enabled."
  default     = "false"
  type        = string
}

variable "config_rules" {
  description = "True if the Config Rules should be enabled."
  default     = "false"
  type        = string
}

variable "dlm_rules" {
  description = "True if the DLM Rules should be enabled."
  default     = "false"
  type        = string
}

variable "ec2_rules" {
  description = "True if the EC2 Rules should be enabled."
  default     = "false"
  type        = string
}

variable "ecs_rules" {
  description = "True if the ECS Rules should be enabled."
  default     = "false"
  type        = string
}

variable "emr_rules" {
  description = "True if the EMR Rules should be enabled."
  default     = "false"
  type        = string
}

variable "glue_rules" {
  description = "True if the Glue Rules should be enabled."
  default     = "false"
  type        = string
}

variable "health_rules" {
  description = "True if the Health Rules should be enabled."
  default     = "false"
  type        = string
}

variable "kms_rules" {
  description = "True if the KMS Rules should be enabled."
  default     = "false"
  type        = string
}

variable "macie_rules" {
  description = "True if the Macie Rules should be enabled."
  default     = "false"
  type        = string
}

variable "mediaconvert_rules" {
  description = "True if the MediaConvert Rules should be enabled."
  default     = "false"
  type        = string
}

variable "medialive_rules" {
  description = "True if the MediaLive Rules should be enabled."
  default     = "false"
  type        = string
}

variable "mediastore_rules" {
  description = "True if the MediaStore Rules should be enabled."
  default     = "false"
  type        = string
}

variable "opsworks_rules" {
  description = "True if the OpsWorks Rules should be enabled."
  default     = "false"
  type        = string
}

variable "signer_rules" {
  description = "True if the Signer Rules should be enabled."
  default     = "false"
  type        = string
}

variable "sms_rules" {
  description = "True if the SMS Rules should be enabled."
  default     = "false"
  type        = string
}

variable "ssm_rules" {
  description = "True if the SSM Rules should be enabled."
  default     = "false"
  type        = string
}

variable "storagegateway_rules" {
  description = "True if the StorageGateway Rules should be enabled."
  default     = "false"
  type        = string
}

variable "transcribe_rules" {
  description = "True if the Transcribe Rules should be enabled."
  default     = "false"
  type        = string
}

variable "workspaces_rules" {
  description = "True if the WorkSpaces Rules should be enabled."
  default     = "false"
  type        = string
}

variable "cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "cloudwatchevents_hec_token" {
  description = "CloudWatch Events HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "cloudtrail_hec_token" {
  description = "CloudTrail HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "guardduty_hec_token" {
  description = "GuardDuty HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "securityhub_hec_token" {
  description = "SecurityHub HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "cloudwatchlogs_hec_token" {
  description = "CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "vpcflowlogs_hec_token" {
  description = "The HEC Token for VPCFlowLogs for use with Splunk Endpoint"
  default     = ""
  type        = string
}
variable "splunk_endpoint" {
  description = "Endpoint address for Splunk"
  default     = ""
  type        = string
}

variable "cloudwatch_logs_to_ship" {
  description = "CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

//variable "arn_cloudwatch_logs_to_ship" {
//  description = "arn of the CloudWatch Log Group that you want to ship to Splunk."
//}

variable "subscription_filter_pattern" {
  description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
  default     = "" # nothing is being filtered
}

variable "denodo_subscription_filter_pattern" {
  description = "Filter pattern for the Denodo CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
  default     = "" # nothing is being filtered
}

variable "vpcflowlogs_subscription_filter_pattern" {
  description = "Filter pattern for the CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
  default     = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id}" // nothing is being filtered
}

variable "cloudwatch_log_filter_name" {
  description = "Name of Log Filter for CloudWatch Log subscription to Kinesis Firehose"
  default     = "KinesisSubscriptionFilter"
}

variable "log_stream_name" {
  description = "Name of the CloudWatch log stream for Kinesis Firehose CloudWatch log group"
  default     = "SplunkDelivery"
}

variable "vpcid_to_ship" {
  description = "VPCID flow Logs "
  default     = []
  type        = list(string)
}

variable "vpcflowlogs_rules" {
  description = "True if the vpcflowlogs Rules should be enabled."
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
  default     = "/pm/aws/vpcflowlogs/"
  type        = string
}

variable "denodo_linux_messages_cloudwatch_logs_hec_token" {
  description = "Denodo Linux syslog CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "denodo_linux_secure_cloudwatch_logs_hec_token" {
  description = "Denodo Linux messages CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "denodo_vdp_connections_cloudwatch_logs_hec_token" {
  description = "Denodo VDP Connections CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "denodo_vdp_queries_cloudwatch_logs_hec_token" {
  description = "Denodo VDP Queries CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "denodo_vdp_threads_cloudwatch_logs_hec_token" {
  description = "Denodo VDP Threads CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "denodo_vdp_log_cloudwatch_logs_hec_token" {
  description = "Denodo VDP Log CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "linux_audit_cloudwatchlogs_hec_token" {
  description = "Linux Audit CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "linux_syslog_cloudwatchlogs_hec_token" {
  description = "Linux syslog CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "linux_secure_cloudwatchlogs_hec_token" {
  description = "Linux secure CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "metadataserver_cloudwatchlogs_hec_token" {
  description = "Linux syslog CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "storagegw_cloudwatchlogs_hec_token" {
  description = "Storage Gateway CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "ssm_cloudwatchlogs_hec_token" {
  description = "SSM CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}
variable "sasworkspace_cloudwatchlogs_hec_token" {
  description = "sasworkspace CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "test_splunk_endpoint" {
  description = "Endpoint address for Test Splunk Instance"
  default     = ""
  type        = string
}

variable "linux_audit_cloudwatch_logs_to_ship" {
  description = "Linux Audit CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "linux_audit_cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "linux_syslog_cloudwatch_logs_to_ship" {
  description = "Linux Audit CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "linux_syslog_cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "metadataserver_cloudwatch_logs_to_ship" {
  description = "Linux Audit CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "metadataserver_cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}
variable "storagegw_cloudwatch_logs_to_ship" {
  description = "Storage Gateway CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "storagegw_cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "linux_secure_cloudwatch_logs_to_ship" {
  description = "Linux Secure CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "linux_secure_cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "ssm_cloudwatch_logs_to_ship" {
  description = "SSM CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "ssm_cloudwatchlogs_rules" {
  description = "True if the cloudwatchlogs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "sasworkspace_cloudwatch_logs_to_ship" {
  description = "SAS Workspace CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "sasworkspace_cloudwatchlogs_rules" {
  description = "True if the CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_linux_messages_cloudwatch_logs_rules" {
  description = "True if the Denodo messages CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_linux_messages_cloudwatch_logs_logs_to_ship" {
  description = "Denodo messages CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "denodo_linux_secure_cloudwatch_logs_rules" {
  description = "True if the Denodo Syslog CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_linux_secure_cloudwatch_logs_logs_to_ship" {
  description = "Denodo Syslog CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "denodo_vdp_connections_cloudwatch_logs_rules" {
  description = "True if the Denodo VDP Connections CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_vdp_connections_cloudwatch_logs_logs_to_ship" {
  description = "Denodo Syslog CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "denodo_vdp_queries_cloudwatch_logs_rules" {
  description = "True if the Denodo VDP Queries CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_vdp_queries_cloudwatch_logs_logs_to_ship" {
  description = "Denodo VDP Queries CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "denodo_vdp_threads_cloudwatch_logs_rules" {
  description = "True if the Denodo VDP Threads CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_vdp_threads_cloudwatch_logs_logs_to_ship" {
  description = "Denodo Threads CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "denodo_vdp_log_cloudwatch_logs_rules" {
  description = "True if the Denodo VDP Log CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "denodo_vdp_log_cloudwatch_logs_logs_to_ship" {
  description = "Denodo Log CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "linux_messages_cloudwatchlogs_hec_token" {
  description = "linux messages CloudWatchLogs HEC Token for use with Splunk Endpoint"
  default     = ""
  type        = string
}

variable "linux_messages_cloudwatch_logs_rules" {
  description = "True if the Linux Messages CloudWatch Logs Rules should be enabled."
  default     = "false"
  type        = string
}

variable "linux_messages_cloudwatch_logs_to_ship" {
  description = "linux messages CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "csat_cloudwatch_logs_to_ship" {
  description = "CSAT CloudWatch Log Groups"
  default     = []
  type        = list(string)
}

variable "csat_cloudwatch_logs_rules" {
  description = "CSAT CloudWatch Log used"
  default     = "false"
  type        = string
}

variable "csat_cloudwatch_logs_hec_token" {
  description = "CSAT CloudWatch Log HEC Token"
  default     = ""
  type        = string
}

variable "csat_subscription_filter_pattern" {
  description = "Filter pattern for the CSAT CloudWatch Log Group subscription to the Kinesis Firehose. See [this](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html) for filter pattern info."
  default     = "" # nothing is being filtered
}

variable "dev_account" {
  description = "A flag to identify if this is a dev Account"
  default     = "false"
  type        = string
}

variable "ci_account" {
  description = "A flag to identify if this is a CI Account"
  default     = "true"
  type        = string
}

variable "ci_principals" {
  description = "A list of principals that should be assigned CI user IAM policies"
  default     = []
  type        = list(string)
}
