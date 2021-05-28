resource "aws_lambda_function" "cloudwatch_events_processor" {
  filename         = "${path.module}/files/cloudwatch_events_processor.zip"
  function_name    = "${var.name}-CloudWatch-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/cloudwatch_events_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}
resource "aws_lambda_function" "cloudwatchlogs_processor" {
  count            = var.cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = "${path.module}/files/cloudwatchlogs_processor.zip"
  function_name    = "${var.name}-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "cloudwatchlogs_processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/cloudwatchlogs_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "cloudtrail_events_processor" {
  filename         = "${path.module}/files/cloudtrail_events_processor.zip"
  function_name    = "${var.name}-CloudTrail-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/cloudtrail_events_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "guardduty_events_processor" {
  filename         = "${path.module}/files/guardduty_events_processor.zip"
  function_name    = "${var.name}-GuardDuty-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/guardduty_events_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "securityhub_events_processor" {
  filename         = "${path.module}/files/securityhub_events_processor.zip"
  function_name    = "${var.name}-SecurityHub-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/securityhub_events_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "vpcflowlogs_processor" {
  count            = var.vpcflowlogs_rules == "true" ? 1 : 0
  filename         = "${path.module}/files/vpcflowlogs_processor.zip"
  function_name    = "${var.name}-vpcflowlogs_processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "vpcflowlogs_processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/vpcflowlogs_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "linux_audit_cloudwatchlogs_processor" {
  count            = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = "${path.module}/files/linux_audit_cloudwatchlogs_processor.zip"
  function_name    = "${var.name}-linux-audit-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "linux_audit_cloudwatchlogs_processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/linux_audit_cloudwatchlogs_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "linux_syslog_cloudwatchlogs_processor" {
  count            = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = "${path.module}/files/linux_syslog_cloudwatchlogs_processor.zip"
  function_name    = "${var.name}-linux-syslog-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "linux_syslog_cloudwatchlogs_processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/linux_syslog_cloudwatchlogs_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}

resource "aws_lambda_function" "metadataserver_cloudwatchlogs_processor" {
  count            = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = "${path.module}/files/metadataserver_cloudwatchlogs_processor.zip"
  function_name    = "${var.name}-metadataserver-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "metadataserver_cloudwatchlogs_processor.handler"
  source_code_hash = filebase64sha256("${path.module}/files/metadataserver_cloudwatchlogs_processor.zip")
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 512
}
