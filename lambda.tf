resource "aws_lambda_function" "default_processing_lambda" {
  count            = var.default_processing_lamba == "true" ? 1 : 0
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.name}-default-log-processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512
  publish          = true
  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

data "template_file" "lambda_template" {
  template = file("${path.module}/files/processor.py.tpl")
  vars = {
    module_name = var.name
  }
}

data "archive_file" "lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/processor.zip"
  source_content          = data.template_file.lambda_template.rendered
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "cloudwatch_events_processor" {
  filename         = data.archive_file.cloudwatch_events_processor_lambda_zip.output_path
  function_name    = "${var.name}-CloudWatch-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.cloudwatch_events_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512
}

data "archive_file" "cloudwatch_events_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/cloudwatch_events_processor.zip"
  source_content          = "${path.module}/files/cloudwatch_events_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "cloudwatchlogs_processor" {
  count            = var.cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.name}-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

resource "aws_lambda_function" "cloudtrail_events_processor" {
  count            = var.cloudtrail_rules == "true" ? 1 : 0
  filename         = data.archive_file.cloudtrail_events_processor_lambda_zip.output_path
  function_name    = "${var.name}-CloudTrail-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.cloudtrail_events_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512
}

data "archive_file" "cloudtrail_events_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/cloudtrail_events_processor.zip"
  source_content          = "${path.module}/files/cloudtrail_events_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "guardduty_events_processor" {
  count            = var.guardduty_rules == "true" ? 1 : 0
  filename         = data.archive_file.guardduty_events_processor_lambda_zip.output_path
  function_name    = "${var.name}-GuardDuty-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.guardduty_events_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512
}

data "archive_file" "guardduty_events_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/guardduty_events_processor.zip"
  source_content          = "${path.module}/files/guardduty_events_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "securityhub_events_processor" {
  count            = var.securityhub_rules == "true" ? 1 : 0
  filename         = data.archive_file.securityhub_events_processor_lambda_zip.output_path
  function_name    = "${var.name}-SecurityHub-Events-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.securityhub_events_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512
}

data "archive_file" "securityhub_events_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/securityhub_events_processor.zip"
  source_content          = "${path.module}/files/securityhub_events_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "vpcflowlogs_processor" {
  count            = var.vpcflowlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.vpcflowlogs_processor_lambda_zip.output_path
  function_name    = "${var.name}-vpcflowlogs_processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "vpcflowlogs_processor.handler"
  source_code_hash = data.archive_file.vpcflowlogs_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512
}

data "archive_file" "vpcflowlogs_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/vpcflowlogs_processor.zip"
  source_content          = "${path.module}/files/vpcflowlogs_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "linux_audit_cloudwatchlogs_processor" {
  count            = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.name}-linux-audit-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

resource "aws_lambda_function" "linux_syslog_cloudwatchlogs_processor" {
  count            = var.linux_syslog_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.name}-linux-syslog-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

resource "aws_lambda_function" "metadataserver_cloudwatchlogs_processor" {
  count            = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.metadataserver_cloudwatchlogs_processor_lambda_zip.output_path
  function_name    = "${var.name}-metadataserver-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "metadataserver_cloudwatchlogs_processor.handler"
  source_code_hash = data.archive_file.metadataserver_cloudwatchlogs_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

data "archive_file" "metadataserver_cloudwatchlogs_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/metadataserver_cloudwatchlogs_processor.zip"
  source_content          = "${path.module}/files/metadataserver_cloudwatchlogs_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "storagegw_cloudwatchlogs_processor" {
  count            = var.storagegw_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.storagegw_cloudwatchlogs_processor_lambda_zip.output_path
  function_name    = "${var.name}-storagegw-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "storagegw_cloudwatchlogs_processor.handler"
  source_code_hash = data.archive_file.storagegw_cloudwatchlogs_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

data "archive_file" "storagegw_cloudwatchlogs_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/storagegw_cloudwatchlogs_processor.zip"
  source_content          = "${path.module}/files/storagegw_cloudwatchlogs_processor.py"
  source_content_filename = "processor.py"
}

resource "aws_lambda_function" "linux_secure_cloudwatchlogs_processor" {
  count            = var.linux_secure_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.name}-linux_secure-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "processor.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

resource "aws_lambda_function" "ssm_cloudwatchlogs_processor" {
  count            = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.ssm_cloudwatchlogs_processor_lambda_zip.output_path
  function_name    = "${var.name}-ssm-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "ssm_cloudwatchlogs_processor.handler"
  source_code_hash = data.archive_file.ssm_cloudwatchlogs_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

data "archive_file" "ssm_cloudwatchlogs_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/ssm_cloudwatchlogs_processor.zip"
  source_content          = "${path.module}/files/ssm_cloudwatchlogs_processor.py"
  source_content_filename = "processor.py"
}


resource "aws_lambda_function" "sasworkspace_cloudwatchlogs_processor" {
  count            = var.sasworkspace_cloudwatchlogs_rules == "true" ? 1 : 0
  filename         = data.archive_file.sasworkspace_cloudwatchlogs_processor_lambda_zip.output_path
  function_name    = "${var.name}-sasworkspace-CloudWatchlogs-Processor"
  role             = aws_iam_role.events_processor.arn
  handler          = "sasworkspace_cloudwatchlogs_processor.handler"
  source_code_hash = data.archive_file.sasworkspace_cloudwatchlogs_processor_lambda_zip.output_base64sha256
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      TZ = "Europe/London"
    }
  }
}

data "archive_file" "sasworkspace_cloudwatchlogs_processor_lambda_zip" {
  type                    = "zip"
  output_path             = "${path.cwd}/files/sasworkspace_cloudwatchlogs_processor.zip"
  source_content          = "${path.module}/files/sasworkspace_cloudwatchlogs_processor.py"
  source_content_filename = "processor.py"
}
