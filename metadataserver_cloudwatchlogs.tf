# Create the stream
resource "aws_cloudwatch_log_stream" "metadataserver_kinesis_logs" {
  count          = var.metadataserver_cloudwatchlogs_rules == "true" ? 1 : 0
  name           = var.log_stream_name
  log_group_name = aws_cloudwatch_log_group.metadataserver_cloudwatchlogs_firehose[0].name
}

#Create the subscription filter
resource "aws_cloudwatch_log_subscription_filter" "metadataserver_cloudwatchlogs_to_firehose" {
  count           = length(var.metadataserver_cloudwatch_logs_to_ship)
  name            = "${var.name}-cloudwatchlogs-to-firehose"
  role_arn        = aws_iam_role.metadataserver_cloudwatch_to_firehose_trust[0].arn
  destination_arn = aws_kinesis_firehose_delivery_stream.metadataserver_cloudwatchlogs_firehose[0].arn
  log_group_name  = var.metadataserver_cloudwatch_logs_to_ship[count.index]
  filter_pattern  = var.subscription_filter_pattern
  distribution    = "Random"
}
