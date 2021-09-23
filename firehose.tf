resource "aws_kinesis_firehose_delivery_stream" "cloudwatch_events" {
  name        = "${var.name}.events"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.cloudwatch_events_firehose.name
      log_stream_name = aws_cloudwatch_log_stream.cloudwatch_events_firehose.name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.cloudwatchevents_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.cloudwatch_events_processor.arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudwatch_events_firehose" {
  name = "/pm/aws/cloudwatch/"
}

resource "aws_cloudwatch_log_stream" "cloudwatch_events_firehose" {
  log_group_name = aws_cloudwatch_log_group.cloudwatch_events_firehose.name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "cloudtrail_events_firehose" {
  name        = "${var.name}.cloudtrail"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.cloudtrail_events_firehose.name
      log_stream_name = aws_cloudwatch_log_stream.cloudtrail_events_firehose.name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.cloudtrail_hec_token
    hec_endpoint_type = "Raw"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "false"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.cloudtrail_events_processor.arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail_events_firehose" {
  name = "/pm/aws/cloudtrail/"
}

resource "aws_cloudwatch_log_stream" "cloudtrail_events_firehose" {
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events_firehose.name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "guardduty_events_firehose" {
  name        = "${var.name}.guardduty"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.guardduty_events_firehose.name
      log_stream_name = aws_cloudwatch_log_stream.guardduty_events_firehose.name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.guardduty_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.guardduty_events_processor.arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "guardduty_events_firehose" {
  name = "/pm/aws/guardduty/"
}

resource "aws_cloudwatch_log_stream" "guardduty_events_firehose" {
  log_group_name = aws_cloudwatch_log_group.guardduty_events_firehose.name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "securityhub_events_firehose" {
  name        = "${var.name}.securityhub"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.securityhub_events_firehose.name
      log_stream_name = aws_cloudwatch_log_stream.securityhub_events_firehose.name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.securityhub_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.securityhub_events_processor.arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "securityhub_events_firehose" {
  name = "/pm/aws/securityhub/"
}

resource "aws_cloudwatch_log_stream" "securityhub_events_firehose" {
  log_group_name = aws_cloudwatch_log_group.securityhub_events_firehose.name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "cloudwatchlogs_firehose" {
  count       = var.cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudwatchlogs_firehose" {
  count = var.cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/cloudwatch-logs/"
}

resource "aws_cloudwatch_log_stream" "cloudwatchlogs_firehose" {
  count          = var.cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "vpcflowlogs_firehose" {
  count       = var.vpcflowlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.vpcflowlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.vpcflowlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.vpcflowlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.vpcflowlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.vpcflowlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "vpcflowlogs_firehose" {
  count = var.vpcflowlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/vpcflowlogs/"
}

resource "aws_cloudwatch_log_stream" "vpcflowlogs_firehose" {
  count          = var.vpcflowlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.vpcflowlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "linux_audit_cloudwatchlogs_firehose" {
  count       = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.linux_audit_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.linux_audit_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.linux_audit_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.linux_audit_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.linux_audit_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "linux_audit_cloudwatchlogs_firehose" {
  count = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/linux-audit/"
}

resource "aws_cloudwatch_log_stream" "linux_audit_cloudwatchlogs_firehose" {
  count          = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.linux_audit_cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "linux_syslog_cloudwatchlogs_firehose" {
  count       = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.linux_syslog_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.linux_syslog_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.linux_syslog_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.linux_syslog_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.linux_syslog_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "linux_syslog_cloudwatchlogs_firehose" {
  count = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/linux-syslog/"
}

resource "aws_cloudwatch_log_stream" "linux_syslog_cloudwatchlogs_firehose" {
  count          = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.linux_syslog_cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "metadataserver_cloudwatchlogs_firehose" {
  count       = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.metadataserver_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.metadataserver_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.metadataserver_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.metadataserver_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.metadataserver_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "metadataserver_cloudwatchlogs_firehose" {
  count = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/sas/metadataserver/"
}

resource "aws_cloudwatch_log_stream" "metadataserver_cloudwatchlogs_firehose" {
  count          = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.metadataserver_cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "storagegw_cloudwatchlogs_firehose" {
  count       = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.storagegw_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.storagegw_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.storagegw_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.storagegw_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.storagegw_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "storagegw_cloudwatchlogs_firehose" {
  count = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/storagegw/"
}

resource "aws_cloudwatch_log_stream" "storagegw_cloudwatchlogs_firehose" {
  count          = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.storagegw_cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "linux_secure_cloudwatchlogs_firehose" {
  count       = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.linux_secure_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.linux_secure_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.linux_secure_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.linux_secure_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.linux_secure_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "linux_secure_cloudwatchlogs_firehose" {
  count = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/linux-secure/"
}

resource "aws_cloudwatch_log_stream" "linux_secure_cloudwatchlogs_firehose" {
  count          = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.linux_secure_cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "ssm_cloudwatchlogs_firehose" {
  count       = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.ssm_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.ssm_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.ssm_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.ssm_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.ssm_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "ssm_cloudwatchlogs_firehose" {
  count = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/aws/ssm/"
}

resource "aws_cloudwatch_log_stream" "ssm_cloudwatchlogs_firehose" {
  count          = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.ssm_cloudwatchlogs_firehose[0].name
  name           = var.name
}

resource "aws_kinesis_firehose_delivery_stream" "sasworkspace_cloudwatchlogs_firehose" {
  count       = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  name        = "${var.name}.sasworkspace_cloudwatchlogs"
  destination = "splunk"

  s3_configuration {
    bucket_arn = aws_s3_bucket.events_firehose_backups.arn
    role_arn   = aws_iam_role.firehose_backup_s3.arn
    //    kms_key_arn = aws_kms_key.events_firehose_backups.arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.sasworkspace_cloudwatchlogs_firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.sasworkspace_cloudwatchlogs_firehose[0].name
    }
  }

  splunk_configuration {
    hec_endpoint      = var.splunk_endpoint
    hec_token         = var.sasworkspace_cloudwatchlogs_hec_token
    hec_endpoint_type = "Event"
    s3_backup_mode    = "FailedEventsOnly"

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.sasworkspace_cloudwatchlogs_processor[0].arn}:$LATEST"
        }

        parameters {
          parameter_name  = "RoleArn"
          parameter_value = aws_iam_role.events_processor.arn
        }

      }
    }
  }
}

resource "aws_cloudwatch_log_group" "sasworkspace_cloudwatchlogs_firehose" {
  count = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  name  = "/pm/sas/sasworkspace/"
}

resource "aws_cloudwatch_log_stream" "sasworkspace_cloudwatchlogs_firehose" {
  count          = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.sasworkspace_cloudwatchlogs_firehose[0].name
  name           = var.name
}
