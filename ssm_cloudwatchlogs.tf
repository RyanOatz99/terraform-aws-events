# Create the stream
resource "aws_cloudwatch_log_stream" "ssm_kinesis_logs" {
  count          = var.ssm_cloudwatchlogs_rules == "true" ? 1 : 0
  name           = var.log_stream_name
  log_group_name = aws_cloudwatch_log_group.ssm_cloudwatchlogs_firehose[0].name
}

#Create the subscription filter
resource "aws_cloudwatch_log_subscription_filter" "ssm_cloudwatchlogs_to_firehose" {
  count           = length(var.ssm_cloudwatch_logs_to_ship)
  name            = "${var.name}-cloudwatchlogs-audit-to-firehose"
  role_arn        = aws_iam_role.ssm_cloudwatch_to_firehose_trust[0].arn
  destination_arn = aws_kinesis_firehose_delivery_stream.ssm_cloudwatchlogs_firehose[0].arn
  log_group_name  = var.ssm_cloudwatch_logs_to_ship[count.index]
  filter_pattern  = var.subscription_filter_pattern
  distribution    = "Random"
}
