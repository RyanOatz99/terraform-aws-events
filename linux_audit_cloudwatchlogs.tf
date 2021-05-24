# Create the stream
resource "aws_cloudwatch_log_stream" "linux_audit_kinesis_logs" {
  count          = var.linux_audit_cloudwatchlogs_rules == "true" ? 1 : 0
  name           = var.log_stream_name
  log_group_name = aws_cloudwatch_log_group.linux_audit_cloudwatchlogs_firehose[0].name
}

#Create the subscription filter
resource "aws_cloudwatch_log_subscription_filter" "linux_audit_cloudwatchlogs_to_firehose" {
  count           = length(var.linux_audit_cloudwatch_logs_to_ship)
  name            = "${var.name}-cloudwatchlogs-to-firehose"
  role_arn        = aws_iam_role.linux_audit_cloudwatch_to_firehose_trust[0].arn
  destination_arn = aws_kinesis_firehose_delivery_stream.linux_audit_cloudwatchlogs_firehose[0].arn
  log_group_name  = var.linux_audit_cloudwatch_logs_to_ship[count.index]
  filter_pattern  = var.subscription_filter_pattern
  distribution    = "Random"
}
