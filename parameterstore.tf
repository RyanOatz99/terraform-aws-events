resource "aws_ssm_parameter" "processing_lambda_config" {
  name        = "/pm/processor/config-${var.name}"
  description = "Config object for the Protective Monitoring Processor"
  type        = "SecureString"
  value       = jsonencode(local.processing_lambda_config)
  key_id      = aws_kms_key.processing_lambda.arn
}

resource "aws_kms_key" "processing_lambda" {
  description             = "Processing Lambda Config"
  deletion_window_in_days = 14
}
