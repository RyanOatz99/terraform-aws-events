# Firehose S3 Backup Role & Policies
resource "aws_iam_role" "firehose_backup_s3" {
  name        = "${var.name}FirehoseBackupS3Role"
  description = "Firehose Backup S3 Role"

  assume_role_policy = data.aws_iam_policy_document.firehose_backup_s3_assume.json
}

data "aws_iam_policy_document" "firehose_backup_s3_assume" {
  statement {
    sid     = "AllowFirehoseAssumeFirehoseBackupS3Role"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["firehose.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "firehose_backup_s3_access" {
  statement {
    sid = "AllowGetGlueTableVersions"
    actions = [
      "glue:GetTable",
      "glue:GetTableVersion",
      "glue:GetTableVersions"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    sid = "AllowS3BucketAccess"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject"
    ]
    effect = "Allow"
    resources = [
      aws_s3_bucket.events_firehose_backups.arn,
      "${aws_s3_bucket.events_firehose_backups.arn}/*"
    ]
  }
  statement {
    sid = "AllowInvokeLambdaFunction"
    actions = [
      "lambda:InvokeFunction",
      "lambda:GetFunctionConfiguration"
    ]
    effect = "Allow"
    //    resources = [aws_lambda_function.events_processor.arn]
    resources = ["*"]
  }
  statement {
    sid = "AllowCreateLogEvents"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    sid       = "AllowKinesisDeliveryStreamAccessCWE"
    actions   = ["*"]
    effect    = "Allow"
    resources = [aws_kinesis_firehose_delivery_stream.cloudwatch_events.arn]
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.securityhub_events_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessSHELogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.securityhub_events_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.guardduty_events_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessGDELogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.guardduty_events_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.cloudtrail_events_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessCTELogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.cloudtrail_events_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.linux_audit_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessLACWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.linux_audit_cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.ssm_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessSSMCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.ssm_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.linux_syslog_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessSyslogCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.linux_syslog_cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.linux_secure_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessSecureCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.linux_secure_cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.storagegw_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessStoragegwCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.storagegw_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.metadataserver_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessMetadataserverCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.metadataserver_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.sasworkspace_cloudwatchlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccesssasworkspaceCWLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.sasworkspace_cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.vpcflowlogs_firehose

    content {
      sid       = "AllowKinesisDeliveryStreamAccessVPCFlowLogs"
      actions   = ["*"]
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.vpcflowlogs_firehose[0].arn]
    }
  }
  statement {
    sid = "AllowKinesisStreamAccess"
    actions = [
      "kinesis:GetShardIterator",
      "kinesis:GetRecords",
      "kinesis:DescribeStream",
      "kinesis:ListShards"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    sid = ""
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]
    effect    = "Allow"
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["kinesis.eu-west-2.amazonaws.com"]
      variable = "kms:ViaService"
    }
    condition {
      test     = "StringLike"
      values   = ["*"]
      variable = "kms:EncryptionContext:aws:kinesis:arn"
    }
  }
  #  statement {
  #    sid = "AllowKMSEncryptionForFirehoseS3Buckets"
  #    actions = [
  #      "kms:Encrypt",
  #      "kms:ListKeys",
  #      "kms:DescribeKeys",
  #      "kms:ReEncrypt"
  #    ]
  #    effect    = "Allow"
  #    resources = [aws_kms_key.events_firehose_backups.id]
  #  }

  statement {
    sid = "AllowKMSEncryptionForFirehoseS3Buckets"
    actions = [
      "kms:Encrypt",
      "kms:ListKeys",
      "kms:DescribeKeys",
      "kms:ReEncrypt"
    ]
    effect    = "Allow"
    resources = [aws_kms_key.events_firehose_backups.arn]
  }

  statement {
    sid = ""
    actions = [
      "kms:Decrypt"
    ]
    effect    = "Allow"
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = ["s3.eu-west-2.amazonaws.com"]
      variable = "kms:ViaService"
    }
    condition {
      test     = "StringLike"
      values   = [aws_s3_bucket.events_firehose_backups.arn]
      variable = "kms:EncryptionContext:aws:s3:arn"
    }
  }
}

resource "aws_iam_policy" "firehose_s3_backup_access" {
  name   = "${var.name}FirehoseBackupS3Access"
  path   = "/events/"
  policy = data.aws_iam_policy_document.firehose_backup_s3_access.json
}

resource "aws_iam_role_policy_attachment" "firehose_s3_backup_access" {
  role       = aws_iam_role.firehose_backup_s3.name
  policy_arn = aws_iam_policy.firehose_s3_backup_access.arn
}

# Firehose Delivery Role & Policies
resource "aws_iam_role" "firehose_delivery" {
  name        = "${var.name}FirehoseDeliveryRole"
  description = "Firehose Delivery Role"

  assume_role_policy = data.aws_iam_policy_document.firehose_delivery_assume.json
}

data "aws_iam_policy_document" "firehose_delivery_assume" {
  statement {
    sid     = "AllowEventsAssumeFirehoseDeliveryRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["events.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "firehose_delivery_access" {

  statement {
    sid = "AllowKinesisDeliveryStreamAccessCWE"
    actions = [
      "firehose:PutRecord",
    "firehose:PutRecordBatch"]
    effect    = "Allow"
    resources = [aws_kinesis_firehose_delivery_stream.cloudwatch_events.arn]
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.cloudtrail_events_firehose

    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessCTEFlowLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.cloudtrail_events_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.guardduty_events_firehose

    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessGDEFlowLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.guardduty_events_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.securityhub_events_firehose

    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessSHEflowLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.securityhub_events_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.vpcflowlogs_firehose

    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessVPCFlowLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.vpcflowlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.linux_audit_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessLACWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.linux_audit_cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.ssm_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessSSMCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.ssm_cloudwatchlogs_firehose[0].arn]
    }
  }

  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.linux_syslog_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessSyslogCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.linux_syslog_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.linux_secure_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessSecureCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.linux_secure_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.sasworkspace_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccesssasworkspaceCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.sasworkspace_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.storagegw_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessStoragegwCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.storagegw_cloudwatchlogs_firehose[0].arn]
    }
  }
  dynamic "statement" {
    for_each = aws_kinesis_firehose_delivery_stream.metadataserver_cloudwatchlogs_firehose
    content {
      actions = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      sid       = "AllowKinesisDeliveryStreamAccessMetadataserverCWLogs"
      effect    = "Allow"
      resources = [aws_kinesis_firehose_delivery_stream.metadataserver_cloudwatchlogs_firehose[0].arn]
    }
  }
}

resource "aws_iam_policy" "firehose_delivery_access" {
  name   = "${var.name}FirehoseDeliveryAccess"
  path   = "/events/"
  policy = data.aws_iam_policy_document.firehose_delivery_access.json
}

resource "aws_iam_role_policy_attachment" "firehose_delivery_access" {
  role       = aws_iam_role.firehose_delivery.name
  policy_arn = aws_iam_policy.firehose_delivery_access.arn
}

# Firehose Lambda Processor Roles & Policies
resource "aws_iam_role" "events_processor" {
  name        = "${var.name}-ProcessorRole"
  description = "Processor Role"

  assume_role_policy = data.aws_iam_policy_document.firehose_lambda_assume.json
}

data "aws_iam_policy_document" "firehose_lambda_assume" {
  statement {
    sid     = "AllowLamdaAssumeFirehoseLambdaRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["lambda.amazonaws.com", "firehose.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "firehose_lambda_access" {
  statement {
    sid = "AllowLambdaInvoke"
    actions = [
      "lambda:InvokeFunction"
    ]
    effect = "Allow"
    //    resources = [aws_lambda_function.events_processor.arn]  // TODO: Return here to limit to specific Lambdas when tested
    resources = ["*"]
  }
  statement {
    sid = "AllowKinesisLogging"
    actions = [
      "kinesis:GetRecords",
      "kinesis:GetShardIterator",
      "kinesis:DescribeStream",
      "kinesis:ListStreams"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    actions = [
      "ssm:DescribeParameters",
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    actions = [
      "ssm:GetParameter",
    ]
    effect    = "Allow"
    resources = [aws_ssm_parameter.processing_lambda_config.arn]
  }
  statement {
    actions = [
      "kms:Decrypt",
    ]
    effect    = "Allow"
    resources = [aws_kms_key.processing_lambda.arn]
  }
}

data "aws_iam_policy_document" "events_firehose_backups" {
  statement {
    sid     = "DenyUnsecuredTransport"
    effect  = "Deny"
    actions = ["*"]
    resources = [
      aws_s3_bucket.events_firehose_backups.arn,
      "${aws_s3_bucket.events_firehose_backups.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      values   = ["false"]
      variable = "aws:SecureTransport"
    }
  }
}

resource "aws_iam_policy" "firehose_lambda_access" {
  name   = "${var.name}FirehoseLambdaAccess"
  path   = "/events/"
  policy = data.aws_iam_policy_document.firehose_lambda_access.json
}

resource "aws_iam_role_policy_attachment" "firehose_lambda_access" {
  role       = aws_iam_role.events_processor.name
  policy_arn = aws_iam_policy.firehose_lambda_access.arn
}

resource "aws_iam_role_policy_attachment" "firehose_lambda_execution" {
  role       = aws_iam_role.events_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "events_firehose_backups" {
  statement {
    sid     = "DenyUnsecuredTransport"
    effect  = "Deny"
    actions = ["*"]
    resources = [
      aws_s3_bucket.events_firehose_backups.arn,
      "${aws_s3_bucket.events_firehose_backups.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      values   = ["false"]
      variable = "aws:SecureTransport"
    }

  }
}

data "aws_iam_policy_document" "s3_bucket_cmk" {
  statement {
    sid    = "EnableIAMPermissionsFireHose"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:ListKeys",
      "kms:DescribeKeys",
      "kms:ReEncrypt"
    ]
    resources = ["*"]

    principals {
      identifiers = [aws_iam_role.firehose_backup_s3.arn]
      type        = "AWS"
    }
  }
  statement {
    sid       = "EnableIAMPermissionsCIUser"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      identifiers = [
        "arn:aws:iam::${local.account}:user/breakglass",
        "arn:aws:iam::${local.account}:role/ci",
      ]
      type = "AWS"
    }
  }
  dynamic "statement" {
    for_each = var.dev_account == "true" ? [""] : []

    content {
      sid       = "EnableIAMPermissionsCIUserDevAccountOnly"
      effect    = "Allow"
      actions   = ["kms:*"]
      resources = ["*"]

      principals {
        identifiers = [
          "arn:aws:iam::${local.account}:role/administrator",
        ]
        type = "AWS"
      }
    }
  }
  dynamic "statement" {
    for_each = var.dev_account == "false" ? [""] : []

    content {
      sid       = "EnableIAMPermissionsCIUserAdminReadOnly"
      effect    = "Allow"
      actions   = ["kms:*"]
      resources = ["*"]

      principals {
        identifiers = [
          "arn:aws:iam::${local.account}:role/administrator-read-only",
        ]
        type = "AWS"
      }
    }
  }
}
resource "aws_iam_role" "cloudwatch_to_firehose_trust" {
  count       = var.cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-CWLtoKinesisFirehoseRole"
  description = "Role for CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "cloudwatchlogs_firehose_assume" {
  count = var.cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "cloudwatch_to_firehose_access_policy" {
  count = var.cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "cloudwatch_to_firehose_access_policy" {
  count       = var.cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}CloudWatchtoFirehoseAccess"
  description = "Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "cloudwatch_to_fh" {
  count      = var.cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "vpcflowlogs_cloudwatch_to_firehose_trust" {
  count       = var.vpcflowlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-VPCFlowtoKinesisFirehoseRole"
  description = "Role for te logs CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.vpcflowlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "vpcflowlogs_firehose_assume" {
  count = var.vpcflowlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowVPCFlowLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com", "vpc-flow-logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "vpcflowlogs_cloudwatch_to_firehose_access_policy" {
  count = var.vpcflowlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.vpcflowlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.vpcflowlogs_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "vpcflowlogs_cloudwatch_to_firehose_access_policy" {
  count       = var.vpcflowlogs_rules == "true" ? 1 : 0
  name        = "${var.name}vpcflowtoFirehoseAccess"
  description = "VPCFlow to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.vpcflowlogs_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "vpcflow_cloudwatch_to_firehose" {
  count      = var.vpcflowlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.vpcflowlogs_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.vpcflowlogs_cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "vpcflowlogs_to_cloudwatch_trust" {
  count       = var.vpcflowlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-VPCFlowtoCloudWatchRole"
  description = "Role for Flow logs to CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.vpcflowlogs_assume[0].json
}

data "aws_iam_policy_document" "vpcflowlogs_assume" {
  count = var.vpcflowlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowVPCFlowLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["vpc-flow-logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "vpcflowlogs_to_Cloudwatch_access_policy" {
  count = var.vpcflowlogs_rules == "true" ? 1 : 0
  statement {
    sid = "AllowvpcFlowLogging"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:CreateLogGroup",
      "logs:PutLogEvents"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
}

resource "aws_iam_policy" "vpcflowlogs_cloudwatch_access_policy" {
  count       = var.vpcflowlogs_rules == "true" ? 1 : 0
  name        = "${var.name}vpcflowtoCloudWatchAccess"
  description = "VPCFlow to CloudWatch Subscription Policy"
  policy      = data.aws_iam_policy_document.vpcflowlogs_to_Cloudwatch_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "vpcflow_cloudwatch" {
  count      = var.vpcflowlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.vpcflowlogs_to_cloudwatch_trust[0].name
  policy_arn = aws_iam_policy.vpcflowlogs_cloudwatch_access_policy[0].arn
}

resource "aws_iam_role" "linux_audit_cloudwatch_to_firehose_trust" {
  count       = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-LACWLtoKinesisFirehoseRole"
  description = "Role for Linux Audit CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.linux_audit_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "linux_audit_cloudwatchlogs_firehose_assume" {
  count = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowLACloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "linux_audit_cloudwatch_to_firehose_access_policy" {
  count = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.linux_audit_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.linux_audit_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "linux_audit_cloudwatch_to_firehose_access_policy" {
  count       = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}LACloudWatchtoFirehoseAccess"
  description = "linux audit Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.linux_audit_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "linux_audit_cloudwatch_to_firehose" {
  count      = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.linux_audit_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.linux_audit_cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "linux_syslog_cloudwatch_to_firehose_trust" {
  count       = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-LSCWLtoKinesisFirehoseRole"
  description = "Role for Linux Syslog CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.linux_syslog_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "linux_syslog_cloudwatchlogs_firehose_assume" {
  count = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowLSCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "linux_syslog_cloudwatch_to_firehose_access_policy" {
  count = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.linux_syslog_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.linux_syslog_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "linux_syslog_cloudwatch_to_firehose_access_policy" {
  count       = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}LSCloudWatchtoFirehoseAccess"
  description = "linux syslog Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.linux_syslog_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "linux_syslog_cloudwatch_to_firehose" {
  count      = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.linux_syslog_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.linux_syslog_cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "metadataserver_cloudwatch_to_firehose_trust" {
  count       = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-metadataserverCWLtoKinesisFirehoseRole"
  description = "Role for Metadataserver CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.metadataserver_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "metadataserver_cloudwatchlogs_firehose_assume" {
  count = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowMetadataserverCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "metadataserver_cloudwatch_to_firehose_access_policy" {
  count = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.metadataserver_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.metadataserver_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "metadataserver_cloudwatch_to_firehose_access_policy" {
  count       = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}metadataserverCloudWatchtoFirehoseAccess"
  description = "Metadataserver Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.metadataserver_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "metadataserver_cloudwatch_to_firehose" {
  count      = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.metadataserver_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.metadataserver_cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "storagegw_cloudwatch_to_firehose_trust" {
  count       = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-storagegwCWLtoKinesisFirehoseRole"
  description = "Role for Storage Gateway CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.storagegw_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "storagegw_cloudwatchlogs_firehose_assume" {
  count = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowStoragegwCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "storagegw_cloudwatch_to_firehose_access_policy" {
  count = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.storagegw_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.storagegw_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "storagegw_cloudwatch_to_firehose_access_policy" {
  count       = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-storagegwCloudWatchtoFirehoseAccess"
  description = "Storage Gateway Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.storagegw_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "storagegw_cloudwatch_to_firehose" {
  count      = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.storagegw_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.storagegw_cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "linux_secure_cloudwatch_to_firehose_trust" {
  count       = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-LSCCWLtoKinesisFirehoseRole"
  description = "Role for Linux Secure CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.linux_secure_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "linux_secure_cloudwatchlogs_firehose_assume" {
  count = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowLSCCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "linux_secure_cloudwatch_to_firehose_access_policy" {
  count = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.linux_secure_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.linux_secure_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "linux_secure_cloudwatch_to_firehose_access_policy" {
  count       = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}LSCCloudWatchtoFirehoseAccess"
  description = "linux secure Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.linux_secure_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "linux_secure_cloudwatch_to_firehose" {
  count      = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.linux_secure_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.linux_secure_cloudwatch_to_firehose_access_policy[0].arn
}

resource "aws_iam_role" "ssm_cloudwatch_to_firehose_trust" {
  count       = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-SSMCWLtoKinesisFirehoseRole"
  description = "Role for SSM CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.ssm_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "ssm_cloudwatchlogs_firehose_assume" {
  count = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowSSMCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "ssm_cloudwatch_to_firehose_access_policy" {
  count = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.ssm_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.ssm_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "ssm_cloudwatch_to_firehose_access_policy" {
  count       = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}SSMCloudWatchtoFirehoseAccess"
  description = "SSM Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.ssm_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "ssm_cloudwatch_to_firehose" {
  count      = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.ssm_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.ssm_cloudwatch_to_firehose_access_policy[0].arn
}
resource "aws_iam_role" "sasworkspace_cloudwatch_to_firehose_trust" {
  count       = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}-sasworkspaceCWLtoKinesisFirehoseRole"
  description = "Role for sasworkspace CloudWatch Log Group subscription"

  assume_role_policy = data.aws_iam_policy_document.sasworkspace_cloudwatchlogs_firehose_assume[0].json
}

data "aws_iam_policy_document" "sasworkspace_cloudwatchlogs_firehose_assume" {
  count = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    sid     = "AllowsasworkspaceCloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "sasworkspace_cloudwatch_to_firehose_access_policy" {
  count = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  statement {
    actions = [
      "firehose:*",
    ]
    effect = "Allow"
    resources = [
      aws_kinesis_firehose_delivery_stream.sasworkspace_cloudwatchlogs_firehose[0].arn,
    ]
  }
  statement {
    actions = [
      "iam:PassRole",
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.sasworkspace_cloudwatch_to_firehose_trust[0].arn,
    ]
  }
}

resource "aws_iam_policy" "sasworkspace_cloudwatch_to_firehose_access_policy" {
  count       = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}sasworkspaceCloudWatchtoFirehoseAccess"
  description = "sasworkspace Cloudwatch to Firehose Subscription Policy"
  policy      = data.aws_iam_policy_document.sasworkspace_cloudwatch_to_firehose_access_policy[0].json
}

resource "aws_iam_role_policy_attachment" "sasworkspace_cloudwatch_to_firehose" {
  count      = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  role       = aws_iam_role.sasworkspace_cloudwatch_to_firehose_trust[0].name
  policy_arn = aws_iam_policy.sasworkspace_cloudwatch_to_firehose_access_policy[0].arn
}
