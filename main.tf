terraform {
  required_version = "~> 0.12.0"
}

locals {
  es_name            = "${var.project_name}-${var.vpc_name}-${var.environment}-elasticsearch"
  identity_pool_name = "${replace(local.es_name, "-", " ")} kibana identity pool"
  domain_prefix      = "${var.project_name}-${var.environment}-"
  domain_name        = var.use_prefix ? join("", [local.domain_prefix, var.domain_name]) : var.domain_name
}

resource "aws_iam_service_linked_role" "es" {
  count            = var.create_iam_service_linked_role ? 1 : 0
  aws_service_name = "es.amazonaws.com"
}

resource "aws_elasticsearch_domain" "es_vpc" {
  depends_on = [aws_iam_service_linked_role.es]

  domain_name           = local.domain_name
  elasticsearch_version = var.es_version


  encrypt_at_rest {
    enabled    = var.encrypt_at_rest
    kms_key_id = var.encrypt_at_rest ? aws_kms_key.kms[0].key_id : ""
  }

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.instance_count
    dedicated_master_enabled = var.instance_count >= var.dedicated_master_threshold ? true : false
    dedicated_master_count   = var.instance_count >= var.dedicated_master_threshold ? 3 : 0
    dedicated_master_type    = var.instance_count >= var.dedicated_master_threshold ? var.dedicated_master_type != "false" ? var.dedicated_master_type : var.instance_type : ""
    zone_awareness_enabled   = var.es_zone_awareness
    zone_awareness_config {
      availability_zone_count = var.num_availability_zones
    }

    warm_enabled = var.warm_enabled
    warm_count   = var.warm_enabled ? var.warm_count : ""
    warm_type    = var.warm_enabled ? var.warm_type : ""
  }

  advanced_options = var.advanced_options

  dynamic "log_publishing_options" {
    for_each = var.log_publishing_options
    content {
      # TF-UPGRADE-TODO: The automatic upgrade tool can't predict
      # which keys might be set in maps assigned here, so it has
      # produced a comprehensive set here. Consider simplifying
      # this after confirming which keys can be set in practice.

      cloudwatch_log_group_arn = log_publishing_options.value.cloudwatch_log_group_arn
      enabled                  = lookup(log_publishing_options.value, "enabled", null)
      log_type                 = log_publishing_options.value.log_type
    }
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption_enabled
  }

  vpc_options {
    security_group_ids = flatten([aws_security_group.allow_443.id, var.security_group_ids])
    subnet_ids         = var.subnet_ids
  }

  ebs_options {
    ebs_enabled = var.ebs_volume_size > 0 ? true : false
    volume_size = var.ebs_volume_size
    volume_type = var.ebs_volume_type
  }

  snapshot_options {
    automated_snapshot_start_hour = var.snapshot_start_hour
  }

  cognito_options {
    enabled          = var.enable_cognito
    user_pool_id     = var.enable_cognito ? aws_cognito_user_pool.kibana[0].id : ""
    identity_pool_id = var.enable_cognito ? aws_cognito_identity_pool.kibana[0].id : ""
    role_arn         = var.enable_cognito ? aws_iam_role.es_assume_role[0].arn : ""
  }

  tags = merge(
    {
      "Domain" = local.domain_name
    },
    var.tags,
  )
}

resource "aws_elasticsearch_domain_policy" "es_vpc_management_access" {
  domain_name     = local.domain_name
  access_policies = length(var.log_pusher_iam_roles) > 0 || var.create_log_pusher_role ? data.aws_iam_policy_document.es_vpc_management_access_base_overlay.json : data.aws_iam_policy_document.es_vpc_management_access_base.json
}

resource "aws_kms_key" "kms" {
  count                   = var.encrypt_at_rest ? 1 : 0
  description             = "KMS key for ${local.es_name}"
  deletion_window_in_days = 10
}

data "aws_iam_policy" "amazon_es_cognito_access" {
  arn = "arn:aws:iam::aws:policy/AmazonESCognitoAccess"
}

resource "aws_iam_role_policy_attachment" "es_cognito_access" {
  count      = var.enable_cognito ? 1 : 0
  role       = aws_iam_role.es_assume_role[0].name
  policy_arn = data.aws_iam_policy.amazon_es_cognito_access.arn
}

resource "aws_iam_role" "es_assume_role" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}-iam-role"

  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_cognito_user_pool" "kibana" {
  count                    = var.enable_cognito ? 1 : 0
  name                     = "${local.es_name}-kibana-user-pool"
  auto_verified_attributes = ["email"]
  admin_create_user_config {
    allow_admin_create_user_only = false
  }
  schema {
    attribute_data_type = "String"
    name                = "email"
    required            = true
  }
  alias_attributes = ["email"]

  lifecycle {
    ignore_changes = all
  }
}

// set user pool domain
resource "aws_cognito_user_pool_domain" "kibana" {
  count        = var.enable_cognito ? 1 : 0
  domain       = local.es_name
  user_pool_id = aws_cognito_user_pool.kibana[0].id
}


resource "aws_cognito_identity_pool" "kibana" {
  count                            = var.enable_cognito ? 1 : 0
  identity_pool_name               = "${replace(local.es_name, "-", " ")} kibana identity pool"
  allow_unauthenticated_identities = false

  lifecycle {
    ignore_changes = [
      cognito_identity_providers
    ]
  }
}

resource "aws_iam_role" "authenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}-AuthenticatedRole"

  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.kibana[0].id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_policy" "authenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}AuthenticatedPolicy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "authenticated_attachment" {
  role       = aws_iam_role.authenticated[0].name
  policy_arn = aws_iam_policy.authenticated[0].arn
}

resource "aws_iam_role" "unauthenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}-UnauthenticatedRole"

  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.kibana[0].id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "unauthenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}UnauthenticatedPolicy"
  role  = aws_iam_role.unauthenticated[0].id

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "mobileanalytics:PutEvents",
          "cognito-sync:*"
        ],
        "Resource": [
          "*"
        ]
      }
    ]
}
EOF
}

resource "aws_iam_role" "developer_authenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}-developer-role"

  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }

  ]
}
EOF
}

resource "aws_iam_role_policy" "developer_authenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}DeveloperAuthenticatedPolicy"
  role  = aws_iam_role.developer_authenticated[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "es:ESHttpGet",
        "es:ESHttpPost"
      ],
      "Resource": [
        "${aws_elasticsearch_domain.es_vpc.arn}",
        "${aws_elasticsearch_domain.es_vpc.arn}/*"
      ]
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "developer_attachment" {
  count      = var.enable_cognito ? 1 : 0
  role       = aws_iam_role.developer_authenticated[0].name
  policy_arn = aws_iam_policy.authenticated[0].arn
}

resource "aws_iam_role" "admin_authenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}-admin-role"

  permissions_boundary = var.permissions_boundary
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }

  ]
}
EOF
}

resource "aws_iam_role_policy" "admin_authenticated" {
  count = var.enable_cognito ? 1 : 0
  name  = "${local.es_name}AdminAuthenticatedPolicy"
  role  = aws_iam_role.admin_authenticated[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "es:ESHttp*"
      ],
      "Resource": [
        "${aws_elasticsearch_domain.es_vpc.arn}",
        "${aws_elasticsearch_domain.es_vpc.arn}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "admin_attachment" {
  count      = var.enable_cognito ? 1 : 0
  role       = aws_iam_role.admin_authenticated[0].name
  policy_arn = aws_iam_policy.authenticated[0].arn
}


resource "aws_cognito_user_group" "admin" {
  count        = var.enable_cognito ? 1 : 0
  name         = "${local.es_name}-admin"
  user_pool_id = aws_cognito_user_pool.kibana[0].id
  precedence   = 1
  role_arn     = aws_iam_role.admin_authenticated[0].arn
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  count            = var.enable_cognito ? 1 : 0
  identity_pool_id = aws_cognito_identity_pool.kibana[0].id

  roles = {
    "authenticated"   = aws_iam_role.authenticated[0].arn,
    "unauthenticated" = aws_iam_role.unauthenticated[0].arn
  }
  lifecycle {
    ignore_changes = [
      role_mapping
    ]
  }
}

resource "aws_iam_user" "log-pusher" {
  count                = var.create_access_keys ? 1 : 0
  name                 = "${local.es_name}-log-pusher"
  path                 = var.path
  force_destroy        = var.force_destroy
  permissions_boundary = var.permissions_boundary
}

resource "aws_iam_access_key" "log-pusher" {
  count   = var.create_access_keys ? 1 : 0
  user    = aws_iam_user.log-pusher[0].name
  pgp_key = var.pgp_key
}

resource "aws_iam_group" "log-pusher" {
  count = var.create_access_keys ? 1 : 0
  name  = "${local.es_name}-log-pusher-group"
}

resource "aws_iam_group_membership" "log-pusher" {
  count = var.create_access_keys ? 1 : 0
  name  = "${local.es_name}-log-pusher-group"

  users = [
    aws_iam_user.log-pusher[0].name
  ]

  group = aws_iam_group.log-pusher[0].name
}

resource "aws_iam_group_policy" "log-pusher-group-policy" {
  name  = "${local.es_name}-log-pusher-group-policy"
  group = aws_iam_group.log-pusher[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "es:ESHttpGet",
        "es:ESHttpHead",
        "es:ESHttpPost",
        "es:ESHttpPut"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_elasticsearch_domain.es_vpc.arn}/",
        "${aws_elasticsearch_domain.es_vpc.arn}/_bulk"
      ]
    }
  ]
}
EOF
}

resource "aws_cognito_user_group" "developer" {
  count        = var.enable_cognito ? 1 : 0
  name         = "${local.es_name}-developer"
  user_pool_id = aws_cognito_user_pool.kibana[0].id
  precedence   = 2
  role_arn     = aws_iam_role.developer_authenticated[0].arn
}

data "aws_iam_policy_document" "ec2_base_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ec2_overlay_assume_role" {
  count       = length(var.worker_node_role) > 0 ? 1 : 0
  source_json = data.aws_iam_policy_document.ec2_base_assume_role.json
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.worker_node_role]
    }
  }
}

resource "aws_iam_role" "log_pusher" {
  count = var.create_log_pusher_role ? 1 : 0
  name  = "${local.es_name}-log-pusher"

  permissions_boundary = var.permissions_boundary
  assume_role_policy   = length(var.worker_node_role) > 0 ? data.aws_iam_policy_document.ec2_overlay_assume_role[0].json : data.aws_iam_policy_document.ec2_base_assume_role.json
}

data "aws_vpc" "vpc" {
  id = var.vpc_id
}

/*Add a new set of data.aws_iam_policy_document, aws_elasticsearch_domain, aws_elasticsearch_domain_policy. Because currently terraform/aws_elasticsearch_domain
does not handle properly null/empty "vpc_options" */

data "aws_iam_policy_document" "es_vpc_management_access_base" {
  statement {
    actions = [
      "es:ESHttpGet",
    ]

    resources = [
      aws_elasticsearch_domain.es_vpc.arn,
      "${aws_elasticsearch_domain.es_vpc.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = var.enable_cognito ? [aws_iam_role.authenticated[0].arn] : distinct(compact(var.management_iam_roles))
    }
  }

  statement {
    actions = [
      "es:ESHttpGet",
      "es:ESHttpDelete",
      "es:ESHttpHead",
      "es:ESHttpPost",
      "es:ESHttpPut"
    ]

    resources = [
      aws_elasticsearch_domain.es_vpc.arn,
      "${aws_elasticsearch_domain.es_vpc.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = var.enable_cognito ? [aws_iam_role.admin_authenticated[0].arn] : distinct(compact(var.management_iam_roles))
    }
  }
}

data "aws_iam_policy_document" "es_vpc_management_access_base_overlay" {
  source_json = data.aws_iam_policy_document.es_vpc_management_access_base.json
  statement {
    actions = [
      "es:ESHttpGet",
      "es:ESHttpHead",
      "es:ESHttpPost",
      "es:ESHttpPut"
    ]

    resources = [
      aws_elasticsearch_domain.es_vpc.arn,
      "${aws_elasticsearch_domain.es_vpc.arn}/_bulk",
    ]

    principals {
      type        = "AWS"
      identifiers = distinct(compact(flatten([var.log_pusher_iam_roles, var.create_log_pusher_role ? length(aws_iam_role.log_pusher) > 0 ? aws_iam_role.log_pusher[0].arn : ""  : ""])))
    }
  }
}

resource "aws_security_group" "allow_443" {
  name        = "${local.es_name}-allow-443"
  description = "Allow port 443 traffic to and from VPC cidr range"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = flatten([[data.aws_vpc.vpc.cidr_block], var.additional_cidr_allow_443])
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = flatten([[data.aws_vpc.vpc.cidr_block], var.additional_cidr_allow_443])
  }

  tags = {
    "Name" = "Allow 443 for ${local.es_name}"
  }
}