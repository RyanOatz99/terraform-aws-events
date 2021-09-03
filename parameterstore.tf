locals {
  processing_lambda_config = {
    patterns = [
      {
        name        = "denodo_vdp_connections"
        streamname  = "idp-dev-events.denodo_vdp_connections_cloudwatchlogs"
        date_regex  = "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.\\d{3})"
        date_format = "%Y-%m-%dT%H:%M:%S.%f"
        sourcetype  = "idp:connection"
        source      = "/denodo/vdp/connections"
        index       = "test"
      },
      {
        name        = "denodo_vdp_queries"
        streamname  = "idp-dev-events.denodo_vdp_queries_cloudwatchlogs"
        date_regex  = "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.\\d{3})"
        date_format = "%Y-%m-%dT%H:%M:%S.%f"
        sourcetype  = "idp:query"
        source      = "/denodo/vdp/queries"
        index       = "test"
      }
    ]
  }
}

//LOOKING FOR  %Y %b %d %H:%M:%S  IN
//vdp	localhost	9997	loginOk	79	2021-09-02T16:05:21.345	-	10.0.8.152	Denodo-Web-Design-Studio	Web-Design-Studio	122	2021-09-02T16:05:21.328	-	admin	admin	-	-	-


resource "aws_ssm_parameter" "processing_lambda_config" {
  name        = "/pm/processor/config"
  description = "Config object for the Protective Monitoring Processor"
  type        = "SecureString"
  value       = jsonencode(local.processing_lambda_config)
  key_id      = aws_kms_key.processing_lambda.arn
}

//resource "aws_lambda_function" "processing_lambda" {
//  filename         = "${path.module}/files/processor.zip"
//  function_name    = "${var.name}-log-processing-test"
//  role             = aws_iam_role.events_processor.arn
//  handler          = "processor.handler"
//  source_code_hash = filebase64sha256("${path.module}/files/processor.zip")
//  runtime          = "python3.7"
//  timeout          = 300
//  memory_size      = 512
//  environment {
//    variables = {
//      TZ = "Europe/London"
//    }
//  }
//}

resource "aws_kms_key" "processing_lambda" {
  description             = "Processing Lambda Config"
  deletion_window_in_days = 14
}

