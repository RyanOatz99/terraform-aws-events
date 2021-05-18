# CloudWatch log group for log streams
resource "aws_cloudwatch_log_group" "flow_log" {
  count             = var.vpcflowlogs_rules == "true" ? 1 : 0
  name              = var.vpcflowlogs_cloudwatch_log_group_name
  retention_in_days = var.vpcflowlogs_cloudwatch_log_group_retention_in_days
}

#Create the subscription filter
resource "aws_cloudwatch_log_subscription_filter" "vpcflowlogs-to-firehose" {
  count           = var.vpcflowlogs_rules == "true" ? 1 : 0
  name            = "${var.name}-vpcflowlogs-to-firehose"
  role_arn        = aws_iam_role.vpcflowlogs_cloudwatch_to_firehose_trust[0].arn
  destination_arn = aws_kinesis_firehose_delivery_stream.vpcflowlogs_firehose[0].arn
  log_group_name  = var.vpcflowlogs_cloudwatch_log_group_name
  filter_pattern  = var.subscription_filter_pattern
  distribution    = "Random"
}

# Create the VPC Flow Log
resource "aws_flow_log" "vpc-flow-logs" {
  count           = length(var.vpcid_to_ship)
  iam_role_arn    = aws_iam_role.vpcflowlogs_to_cloudwatch_trust[0].arn
  log_destination = aws_cloudwatch_log_group.flow_log[0].arn
  traffic_type    = "ALL"
  vpc_id          = var.vpcid_to_ship[count.index]
  log_format      = var.vpcflowlogs_subscription_filter_pattern
  tags            = { name = "vpcflowlogs" }
}


