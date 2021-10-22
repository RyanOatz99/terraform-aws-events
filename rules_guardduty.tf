resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  count       = var.guardduty_rules == "true" ? 1 : 0
  name        = "${var.name}-guardduty-finding"
  description = "${var.name} GuardDuty Finding"

  event_pattern = <<EOF
{
  "detail-type": ["GuardDuty Finding"],
  "source": ["aws.guardduty"]
}
EOF
}

resource "aws_cloudwatch_event_target" "guardduty_finding" {
  count     = var.guardduty_rules == "true" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_finding[0].name
  target_id = "GuardDutyToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.guardduty_events_firehose[0].arn
  role_arn  = aws_iam_role.firehose_delivery.arn
}
