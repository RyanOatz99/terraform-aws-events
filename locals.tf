data "aws_caller_identity" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
}
