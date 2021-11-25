resource "aws_s3_bucket" "events_firehose_backups" {
  bucket = "ons-cia-${var.name}-firehose-backups"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.events_firehose_backups.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "events_firehose_backups" {
  bucket                  = aws_s3_bucket.events_firehose_backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "events_firehose_backups" {
  description             = "This key is used to encrypt bucket objects in the ons-cia-${var.name}-firehose-backups bucket"
  deletion_window_in_days = 14
  enable_key_rotation     = true
  is_enabled              = true
  policy                  = data.aws_iam_policy_document.s3_bucket_cmk.json
}