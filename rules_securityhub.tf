resource "aws_cloudwatch_event_rule" "securityhub" {
  count       = var.securityhub_rules == "true" ? 1 : 0
  name        = "${var.name}-securityhub"
  description = "${var.name} Security Hub Finding"

  event_pattern = <<EOF
{
  "detail-type": ["Security Hub Findings - Imported", "Security Hub Insight Results", "Security Hub Findings - Custom Action"],
  "source": ["aws.securityhub"]
}
EOF
}

resource "aws_cloudwatch_event_target" "securityhub" {
  count     = var.securityhub_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.securityhub[0].name
  target_id = "SecurityHubToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.securityhub_events_firehose.arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}
