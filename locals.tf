data "aws_caller_identity" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id

  processing_lambda_config = {
    patterns = [
      {
        name        = "denodo_vdp_connections"
        streamname  = "${var.name}.denodo_vdp_connections_cloudwatchlogs"
        date_regex  = "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.\\d{3})"
        date_format = "%Y-%m-%dT%H:%M:%S.%f"
        date_time   = "standard"
        utc_offset  = "true"
        sourcetype  = "idp:connection"
        source      = "/denodo/vdp/connections"
        index       = var.index
        host_pos    = 1
      },
      {
        name        = "denodo_vdp_queries"
        streamname  = "${var.name}.denodo_vdp_queries_cloudwatchlogs"
        date_regex  = "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.\\d{3})"
        date_format = "%Y-%m-%dT%H:%M:%S.%f"
        date_time   = "standard"
        utc_offset  = "true"
        sourcetype  = "idp:query"
        source      = "/denodo/vdp/queries"
        index       = var.index
        host_pos    = 1
      },
      {
        name        = "denodo_vdp_threads"
        streamname  = "${var.name}.denodo_vdp_threads_cloudwatchlogs"
        date_regex  = ""
        date_format = ""
        date_time   = ""
        utc_offset  = "true"
        sourcetype  = "idp:threads"
        source      = "/denodo/vdp/threads"
        index       = var.index
        host_pos    = 1
      },
      {
        name        = "denodo_vdp_log"
        streamname  = "${var.name}.denodo_vdp_threads_cloudwatchlogs"
        date_regex  = ""
        date_format = ""
        date_time   = ""
        utc_offset  = "true"
        sourcetype  = "idp:threads"
        source      = "/denodo/vdp/threads"
        index       = var.index
        host_pos    = 1
      },
      {
        name       = "linux_audit"
        streamname = "${var.name}.linux_audit_cloudwatchlogs"
        date_regex = "(\\d{10}\\.\\d{3})"
        date_time  = "epoch"
        utc_offset = "false"
        sourcetype = "linux:audit"
        source     = "/var/log/audit"
        index      = var.index
        host_pos   = 0
      },
      {
        name        = "linux_messages"
        streamname  = "${var.name}.linux_messages_cloudwatchlogs"
        date_regex  = "(\\w{3}\\s{1,2}\\d+ \\d{2}:\\d{2}:\\d{2})"
        date_format = "%Y %b  %d %H:%M:%S"
        date_time   = "standard"
        fix_year    = "true"
        utc_offset  = "false"
        sourcetype  = "linux:messages"
        source      = "/var/log/messages"
        index       = var.index
        host_pos    = 3
      },
      {
        name        = "linux_messages"
        streamname  = "${var.name}.denodo_linux_messages_cloudwatchlogs"
        date_regex  = "(\\w{3}\\s{1,2}\\d+ \\d{2}:\\d{2}:\\d{2})"
        date_format = "%Y %b  %d %H:%M:%S"
        date_time   = "standard"
        fix_year    = "true"
        utc_offset  = "false"
        sourcetype  = "linux:messages"
        source      = "/var/log/messages"
        index       = var.index
        host_pos    = 3
      },
      {
        name        = "linux_secure"
        streamname  = "${var.name}.linux_secure_cloudwatchlogs"
        date_regex  = "(\\w{3}\\s{1,2}\\d+ \\d{2}:\\d{2}:\\d{2})"
        date_format = "%Y %b  %d %H:%M:%S"
        date_time   = "standard"
        fix_year    = "true"
        utc_offset  = "true"
        sourcetype  = "linux:secure"
        source      = "/var/log/secure"
        index       = var.index
        host_pos    = 3
      },
      {
        name        = "linux_secure"
        streamname  = "${var.name}.denodo_linux_secure_cloudwatchlogs"
        date_regex  = "(\\w{3}\\s{1,2}\\d+ \\d{2}:\\d{2}:\\d{2})"
        date_format = "%Y %b  %d %H:%M:%S"
        date_time   = "standard"
        fix_year    = "true"
        utc_offset  = "true"
        sourcetype  = "linux:secure"
        source      = "/var/log/secure"
        index       = var.index
        host_pos    = 3
      },
      {
        name        = "linux_syslog"
        streamname  = "${var.name}.linux_syslog_cloudwatchlogs"
        date_regex  = "(\\w{3}\\s{1,2}\\d+ \\d{2}:\\d{2}:\\d{2})"
        date_format = "%Y %b  %d %H:%M:%S"
        date_time   = "standard"
        fix_year    = "true"
        utc_offset  = "false"
        sourcetype  = "linux:secure"
        source      = "/var/log/secure"
        index       = var.index
        host_pos    = 3
      },
      {
        name        = "csat"
        streamname  = "${var.name}.csat_cloudwatchlogs"
        date_regex  = "(\\d{2}\\/\\d{2}\\/\\d{4} \\d{2}:\\d{2}:\\d{2})"
        date_format = "%d/%m/%Y %H:%M:%S"
        date_time   = "standard"
        fix_year    = ""
        utc_offset  = "false"
        sourcetype  = "cis:csat"
        source      = "/opt/CSAT_Pro/logs/csatlogs/csat.log"
        index       = var.index
        host_pos    = 0
      },
      {
        name        = "test_event"
        streamname  = "copy-cwl-lambda-invoke-input-151025436553-Firehose-8KILJ01Q5OBN"
        date_regex  = "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.\\d{3})"
        date_format = "%Y-%m-%dT%H:%M:%S.%f"
        date_time   = "standard"
        utc_offset  = "true"
        sourcetype  = "idp:query"
        source      = "/denodo/vdp/queries"
        index       = var.index
        host_pos    = 1
      },
    ]
  }
}
