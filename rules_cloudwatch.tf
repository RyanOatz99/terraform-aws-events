resource "aws_cloudwatch_event_rule" "autoscaling" {
  count       = var.autoscaling_rules == "true" ? 1 : 0
  name        = "${var.name}-autoscaling"
  description = "${var.name} AutoScaling"

  event_pattern = <<EOF
{
  "detail-type": ["EC2 Instance Launch Successful", "EC2 Instance Terminate Successful", "EC2 Instance Launch Unsuccessful", "EC2 Instance Terminate Unsuccessful", "EC2 Instance-launch Lifecycle Action", "EC2 Instance-terminate Lifecycle Action"],
  "source": ["aws.autoscaling"]
}
EOF
}

resource "aws_cloudwatch_event_target" "autoscaling" {
  count     = var.autoscaling_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.autoscaling[0].name
  target_id = "AutoScalingToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "batch" {
  count       = var.batch_rules == "true" ? 1 : 0
  name        = "${var.name}-batch"
  description = "${var.name} Batch"

  event_pattern = <<EOF
{
  "detail-type": ["Batch Job State Change"],
  "source": ["aws.batch"]
}
EOF
}

resource "aws_cloudwatch_event_target" "batch" {
  count     = var.batch_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.batch[0].name
  target_id = "BatchToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "cloudwatch_scheduled_events" {
  count       = var.cloudwatch_scheduled_events_rules == "true" ? 1 : 0
  name        = "${var.name}-cw-sched-events"
  description = "${var.name} CloudWatch Scheduled Events"

  event_pattern = <<EOF
{
  "detail-type": ["CloudWatch Events Scheduled Event"],
  "source": ["aws.cloudwatch"]
}
EOF
}

resource "aws_cloudwatch_event_target" "cloudwatch_scheduled_events" {
  count     = var.cloudwatch_scheduled_events_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.cloudwatch_scheduled_events[0].name
  target_id = "CWSchedEventsToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "codebuild" {
  count       = var.codebuild_rules == "true" ? 1 : 0
  name        = "${var.name}-codebuild"
  description = "${var.name} Codebuild"

  event_pattern = <<EOF
{
  "detail-type": ["CodeBuild Build State Change", "CodeBuild Build Phase Change"],
  "source": ["aws.codebuild"]
}
EOF
}

resource "aws_cloudwatch_event_target" "codebuild" {
  count     = var.codebuild_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.codebuild[0].name
  target_id = "CodebuiltToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "codecommit" {
  count       = var.codecommit_rules == "true" ? 1 : 0
  name        = "${var.name}-codecommit"
  description = "${var.name} Codecommit"

  event_pattern = <<EOF
{
  "detail-type": ["CodeCommit Repository State Change", "CodeCommit Comment on Commit", "CodeCommit Comment on Pull Request"],
  "source": ["aws.codecommit"]
}
EOF
}

resource "aws_cloudwatch_event_target" "codecommit" {
  count     = var.codecommit_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.codecommit[0].name
  target_id = "CodecommitToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "codedeploy" {
  count       = var.codedeploy_rules == "true" ? 1 : 0
  name        = "${var.name}-codedeploy"
  description = "${var.name} CodeDeploy"

  event_pattern = <<EOF
{
  "detail-type": ["CodeDeploy Deployment State-change Notification", "CodeDeploy Instance State-change Notification"],
  "source": ["aws.codedeploy"]
}
EOF
}

resource "aws_cloudwatch_event_target" "codedeploy" {
  count     = var.codedeploy_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.codedeploy[0].name
  target_id = "CodeDeployToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "codepipeline" {
  count       = var.codepipeline_rules == "true" ? 1 : 0
  name        = "${var.name}-codepipeline"
  description = "${var.name} CodePipeline"

  event_pattern = <<EOF
{
  "detail-type": ["CodePipeline Stage Execution State Change", "CodePipeline Action Execution State Change", "CodePipeline Pipeline Execution State Change"],
  "source": ["aws.codepipeline"]
}
EOF
}

resource "aws_cloudwatch_event_target" "codepipeline" {
  count     = var.codepipeline_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.codepipeline[0].name
  target_id = "CodePipelineToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "config" {
  count       = var.config_rules == "true" ? 1 : 0
  name        = "${var.name}-config"
  description = "${var.name} Config"

  event_pattern = <<EOF
{
  "detail-type": ["Config Rules Compliance Change", "Config Rules Re-evaluation Status", "Config Configuration Snapshot Delivery Status", "Config Configuration History Delivery Status"],
  "source": ["aws.config"]
}
EOF
}

resource "aws_cloudwatch_event_target" "config" {
  count     = var.config_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.config[0].name
  target_id = "ConfigToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "dlm" {
  count       = var.dlm_rules == "true" ? 1 : 0
  name        = "${var.name}-dlm"
  description = "${var.name} DLM"

  event_pattern = <<EOF
{
  "detail-type": ["DLM Policy State Change"],
  "source": ["aws.dlm"]
}
EOF
}

resource "aws_cloudwatch_event_target" "dlm" {
  count     = var.dlm_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.dlm[0].name
  target_id = "DLMToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "ec2" {
  count       = var.ec2_rules == "true" ? 1 : 0
  name        = "${var.name}-ec2"
  description = "${var.name} EC2"

  event_pattern = <<EOF
{
  "detail-type": ["EC2 Instance State-change Notification", "EBS Volume Notification", "EBS Snapshot Notification", "EC2 Spot Instance Interruption Warning"],
  "source": ["aws.ec2"]
}
EOF
}

resource "aws_cloudwatch_event_target" "ec2" {
  count     = var.ec2_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ec2[0].name
  target_id = "EC2ToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "ecs" {
  count       = var.ecs_rules == "true" ? 1 : 0
  name        = "${var.name}-ecs"
  description = "${var.name} ECS"

  event_pattern = <<EOF
{
  "detail-type": ["ECS Task State Change", "ECS Container Instance State Change"],
  "source": ["aws.ecs"]
}
EOF
}

resource "aws_cloudwatch_event_target" "ecs" {
  count     = var.ecs_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ecs[0].name
  target_id = "ECSToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "emr" {
  count       = var.emr_rules == "true" ? 1 : 0
  name        = "${var.name}-emr"
  description = "${var.name} EMR"

  event_pattern = <<EOF
{
  "detail-type": ["EMR Auto Scaling Policy State Change", "EMR Step Status Change", "EMR Cluster State Change", "EMR Instance Group State Change", "EMR Instance Fleet State Change", "EMR Instance Group Status Notification"],
  "source": ["aws.emr"]
}
EOF
}

resource "aws_cloudwatch_event_target" "emr" {
  count     = var.emr_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.emr[0].name
  target_id = "EMRToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "glue" {
  count       = var.glue_rules == "true" ? 1 : 0
  name        = "${var.name}-glue"
  description = "${var.name} Glue"

  event_pattern = <<EOF
{
  "detail-type": ["Glue Job State Change", "Glue Crawler State Change", "Glue Job Run Status"],
  "source": ["aws.glue"]
}
EOF
}

resource "aws_cloudwatch_event_target" "glue" {
  count     = var.glue_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.glue[0].name
  target_id = "GlueToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "health" {
  count       = var.health_rules == "true" ? 1 : 0
  name        = "${var.name}-health"
  description = "${var.name} Health"

  event_pattern = <<EOF
{
  "detail-type": ["AWS Health Event"],
  "source": ["aws.health"]
}
EOF
}

resource "aws_cloudwatch_event_target" "health" {
  count     = var.health_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.health[0].name
  target_id = "HealthToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "kms" {
  count       = var.kms_rules == "true" ? 1 : 0
  name        = "${var.name}-kms"
  description = "${var.name} KMS"

  event_pattern = <<EOF
{
  "detail-type": ["KMS Imported Key Material Expiration", "KMS CMK Rotation", "KMS CMK Deletion"],
  "source": ["aws.kms"]
}
EOF
}

resource "aws_cloudwatch_event_target" "kms" {
  count     = var.kms_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.kms[0].name
  target_id = "KMSToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "macie" {
  count       = var.macie_rules == "true" ? 1 : 0
  name        = "${var.name}-macie"
  description = "${var.name} Macie"

  event_pattern = <<EOF
{
  "detail-type": ["Macie Alert"],
  "source": ["aws.macie"]
}
EOF
}

resource "aws_cloudwatch_event_target" "macie" {
  count     = var.macie_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.macie[0].name
  target_id = "MacieToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "mediaconvert" {
  count       = var.mediaconvert_rules == "true" ? 1 : 0
  name        = "${var.name}-mediaconvert"
  description = "${var.name} MediaConvert"

  event_pattern = <<EOF
{
  "detail-type": ["MediaConvert Job State Change"],
  "source": ["aws.mediaconvert"]
}
EOF
}

resource "aws_cloudwatch_event_target" "mediaconvert" {
  count     = var.mediaconvert_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.mediaconvert[0].name
  target_id = "MediaConvertToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "medialive" {
  count       = var.medialive_rules == "true" ? 1 : 0
  name        = "${var.name}-medialive"
  description = "${var.name} MediaLive"

  event_pattern = <<EOF
{
  "detail-type": ["MediaLive Channel State Change", "MediaLive Channel Alert"],
  "source": ["aws.medialive"]
}
EOF
}

resource "aws_cloudwatch_event_target" "medialive" {
  count     = var.medialive_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.medialive[0].name
  target_id = "MediaLiveToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "mediastore" {
  count       = var.mediastore_rules == "true" ? 1 : 0
  name        = "${var.name}-mediastore"
  description = "${var.name} MediaStore"

  event_pattern = <<EOF
{
  "detail-type": ["MediaStore Object State Change", "MediaStore Container State Change"],
  "source": ["aws.mediastore"]
}
EOF
}

resource "aws_cloudwatch_event_target" "mediastore" {
  count     = var.mediastore_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.mediastore[0].name
  target_id = "MediaStoreToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "opsworks" {
  count       = var.opsworks_rules == "true" ? 1 : 0
  name        = "${var.name}-opsworks"
  description = "${var.name} OpsWorks"

  event_pattern = <<EOF
{
  "detail-type": ["OpsWorks Instance State Change", "OpsWorks Command State Change", "OpsWorks Deployment State Change", "OpsWorks Alert"],
  "source": ["aws.opsworks"]
}
EOF
}

resource "aws_cloudwatch_event_target" "opsworks" {
  count     = var.opsworks_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.opsworks[0].name
  target_id = "OpsWorksToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "signer" {
  count       = var.signer_rules == "true" ? 1 : 0
  name        = "${var.name}-signer"
  description = "${var.name} Signer"

  event_pattern = <<EOF
{
  "detail-type": ["Signer Job Status Change"],
  "source": ["aws.signer"]
}
EOF
}

resource "aws_cloudwatch_event_target" "signer" {
  count     = var.signer_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.signer[0].name
  target_id = "SignerToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "sms" {
  count       = var.sms_rules == "true" ? 1 : 0
  name        = "${var.name}-sms"
  description = "${var.name} SMS"

  event_pattern = <<EOF
{
  "detail-type": ["Server Migration Job State Change"],
  "source": ["aws.sms"]
}
EOF
}

resource "aws_cloudwatch_event_target" "sms" {
  count     = var.sms_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.sms[0].name
  target_id = "SMSoFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "ssm" {
  count       = var.ssm_rules == "true" ? 1 : 0
  name        = "${var.name}-ssm"
  description = "${var.name} SSM"

  event_pattern = <<EOF
{
  "detail-type": ["EC2 State Manager Association State Change", "EC2 State Manager Instance Association State Change", "EC2 Command Status-change Notification", "EC2 Command Invocation Status-change Notification", "Maintenance Window State-change Notification", "Maintenance Window Target Registration Notification", "Maintenance Window Execution State-change Notification", "Maintenance Window Task Execution State-change Notification", "Maintenance Window Task Target Invocation State-change Notification", "Maintenance Window Task Registration Notification", "EC2 Automation Step Status-change Notification", "EC2 Automation Execution Status-change Notification", "Parameter Store Change", "Configuration Compliance State Change", "Inventory Resource State Change"],
  "source": ["aws.ssm"]
}
EOF
}

resource "aws_cloudwatch_event_target" "ssm" {
  count     = var.ssm_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ssm[0].name
  target_id = "SSMoFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "storagegateway" {
  count       = var.storagegateway_rules == "true" ? 1 : 0
  name        = "${var.name}-storagegateway"
  description = "${var.name} StorageGateway"

  event_pattern = <<EOF
{
  "detail-type": ["Storage Gateway File Upload Event", "Storage Gateway Refresh Cache Event"],
  "source": ["aws.storagegateway"]
}
EOF
}

resource "aws_cloudwatch_event_target" "storagegateway" {
  count     = var.storagegateway_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.storagegateway[0].name
  target_id = "StorageGatewayToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "transcribe" {
  count       = var.transcribe_rules == "true" ? 1 : 0
  name        = "${var.name}-transcribe"
  description = "${var.name} Transcribe"

  event_pattern = <<EOF
{
  "detail-type": ["Transcribe Job State Change"],
  "source": ["aws.transcribe"]
}
EOF
}

resource "aws_cloudwatch_event_target" "transcribe" {
  count     = var.transcribe_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.transcribe[0].name
  target_id = "TranscribeToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "workspaces" {
  count       = var.workspaces_rules == "true" ? 1 : 0
  name        = "${var.name}-workspaces"
  description = "${var.name} WorkSpaces"

  event_pattern = <<EOF
{
  "detail-type": ["WorkSpaces Access"],
  "source": ["aws.workspaces"]
}
EOF
}

resource "aws_cloudwatch_event_target" "workspaces" {
  count     = var.workspaces_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.workspaces[0].name
  target_id = "WorkSpacesToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudwatch_events[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}
