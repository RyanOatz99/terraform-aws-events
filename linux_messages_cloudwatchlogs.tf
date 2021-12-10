#Create the subscription filter
resource "aws_cloudwatch_log_subscription_filter" "linux_messages_cloudwatch_logs_to_firehose" {
  count           = length(var.linux_messages_cloudwatch_logs_to_ship)
  name            = "${var.name}-cloudwatchlogs-messages-to-firehose"
  role_arn        = aws_iam_role.linux_messages_cloudwatch_to_firehose_trust[0].arn
  destination_arn = aws_kinesis_firehose_delivery_stream.linux_messages_cloudwatchlogs_firehose[0].arn
  log_group_name  = var.linux_messages_cloudwatch_logs_to_ship[count.index]
  filter_pattern  = var.subscription_filter_pattern
  distribution    = "Random"
}

resource "aws_kinesis_firehose_delivery_stream" "linux_messages_cloudwatchlogs_firehose" {
  count       = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  name        = "${var.name}.linux_messages_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.linux_messages_cloudwatch_logs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.linux_messages_cloudwatch_logs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint               = var.splunk_endpoint
    hec_token                  = var.linux_messages_cloudwatchlogs_hec_token
    hec_acknowledgment_timeout = 600
    hec_endpoint_type          = "Event"
    s3_backup_mode             = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.linux_messages_cloudwatch_logs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "linux_messages_cloudwatch_logs_firehose" {
  count = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  name  = "/pm/linux-messages/"
}

resource "aws_cloudwatch_log_stream" "linux_messages_cloudwatch_logs_firehose" {
  count          = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.linux_messages_cloudwatch_logs_firehose[0].name
  name           = var.name
}

resource "aws_lambda_function" "linux_messages_cloudwatch_logs_processor" {
  count         = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  filename      = data.archive_file.default_lambda_zip.output_path
  function_name = "${var.name}-linux-messages-CloudWatchlogs-Processor"
  role          = aws_iam_role.events_processor.arn
  handler       = "processor.handler"
  runtime       = "python3.8"
  timeout       = 300
  memory_size   = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

resource "aws_iam_role" "linux_messages_cloudwatch_to_firehose_trust" {
  count       = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  name        = "${var.name}-LMCWLtoKinesisFirehoseRole"
  description = "Role for Linux Messages CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.linux_messages_cloudwatch_logs_firehose_assume[0].json
}

data "aws_iam_policy_document" "linux_messages_cloudwatch_logs_firehose_assume" {
  count = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowLMCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_iam_policy" "linux_messages_cloudwatch_to_firehose_access_policy" {
  count       = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  name        = "${var.name}LinuxMessagesCloudWatchtoFirehoseAccess"
  description = "Linux Messages Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.linux_messages_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "linux_messages_linux_cloudwatch_to_firehose" {
  count      = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  role       = aws_iam_role.linux_messages_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.linux_messages_cloudwatch_to_firehose_access_policy[0].arn
}

data "aws_iam_policy_document" "linux_messages_cloudwatch_to_firehose_access_policy" {
  count = var.linux_messages_cloudwatch_logs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.linux_messages_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.linux_messages_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}
