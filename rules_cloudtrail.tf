resource "aws_cloudwatch_event_rule" "cloudtrail_apicall" {
  count       = var.cloudtrail_rules == "true" ? 1 : 0
  name        = "${var.name}-cloudtrail-apicall"
  description = "${var.name} CloudTrail API Call"

  event_pattern = <<EOF
{
  "detail-type": ["AWS API Call via CloudTrail"]
}
EOF
}

resource "aws_cloudwatch_event_target" "cloudtrail_apicall" {
  count     = var.cloudtrail_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.cloudtrail_apicall[0].name
  target_id = "CloudTrailAPIToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudtrail_events_firehose.arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}

resource "aws_cloudwatch_event_rule" "cloudtrail_consolesignin" {
  count       = var.cloudtrail_rules == "true" ? 1 : 0
  name        = "${var.name}-cloudtrail-console-signin"
  description = "${var.name} CloudTrail Console SignIn"

  event_pattern = <<EOF
{
  "detail-type": ["AWS Console Sign In via CloudTrail"]
}
EOF
}

resource "aws_cloudwatch_event_target" "cloudtrail_consolesignin" {
  count     = var.cloudtrail_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.cloudtrail_consolesignin[0].name
  target_id = "CloudTrailConsoleSiginToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.cloudtrail_events_firehose.arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}
