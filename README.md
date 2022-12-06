# AWS Elasticsearch

Terraform module to create an AWS Elasticsearch cluster with support for AWS Cognito for authentication

## Usage

```hcl

module "eks" {
  instance_count            = 4
  instance_type             = "t2.medium.elasticsearch"
  dedicated_master_type     = "t2.medium.elasticsearch"
  encrypt_at_rest           = false
  es_zone_awareness         = true
  es_version                = "6.7"
  enable_cognito            = true #if you want authentication, see below
  ebs_volume_size           = 35
  subnet_ids                = ["subnet-xxx"]
  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }
}

```

## Authentication

Authentication is provided in 2 parts, you have kibana authentication, and elasticsearch authentication.

### Elasticsearch

This is pretty straight forward, at the moment the access policy is as declared in the module

```hcl

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
      "es:ESHttpPost",
      "es:ESHttpPut"
    ]

    resources = [
      aws_elasticsearch_domain.es_vpc.arn,
      "${aws_elasticsearch_domain.es_vpc.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = distinct(compact(flatten([var.log_pusher_iam_roles, aws_iam_role.log_pusher[0].arn])))
    }
  }
}
```

`es_vpc_management_access_base_overlay` is used to allow an additional arn to push logs to the elasticsearch server.

This provides authenticated users with cognito to use elasticsearch APIs with the respective HTTP methods in actions list.

In order to allow logs to be pushed into es, you will need to provide a list of iam roles using `log_pusher_iam_roles` which are iam users or roles to allow the POST and PUT methods to insert log entries

### enable_cognito

If cognito is enabled, you will need to run the `post-apply.sh` after terraforming.

Key to note, `post-apply.sh` is used with `terragrunt`, if you are using terraform for your infrastructure, modify the script as such

This is a limitation currently with terraform + es + cognito. See [github.com/terraform-providers/terraform-provider-aws/issues/5557](https://github.com/terraform-providers/terraform-provider-aws/issues/5557)

In general we will have to manage the cognito's user client pools outside of terraform as elasticsearch will create one on its own, if we were to make any changes using terraform it will cause the resources to be re-created everytime.

### Cognito

In order for users to access kibana, AWS Cognito is the authentication provider. By default this module creates two groups(admin, developer) to group our users for access control on available HTTP Methods

| Group     | Allowed Methods                |
| --------- | ------------------------------ |
| Admin     | "es:ESHttp*"                   |
| Developer | "es:ESHttpGet","es:ESHttpPost" |

Users are allowed to sign up themselves, however they will be denied from accessing kibana until they are added to atleast the `Developer` group for GET and POST permissions

This will have to be done by accessing the AWS cognito console by the administrator and for him/her to manage the users in each group

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.13 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cognito_identity_pool.kibana](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_identity_pool) | resource |
| [aws_cognito_identity_pool_roles_attachment.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_identity_pool_roles_attachment) | resource |
| [aws_cognito_user_group.admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_group) | resource |
| [aws_cognito_user_group.developer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_group) | resource |
| [aws_cognito_user_pool.kibana](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool) | resource |
| [aws_cognito_user_pool_domain.kibana](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_domain) | resource |
| [aws_elasticsearch_domain.es_vpc](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain) | resource |
| [aws_elasticsearch_domain_policy.es_vpc_management_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain_policy) | resource |
| [aws_iam_access_key.log-pusher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key) | resource |
| [aws_iam_group.log-pusher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group) | resource |
| [aws_iam_group_membership.log-pusher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_membership) | resource |
| [aws_iam_group_policy.log-pusher-group-policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy) | resource |
| [aws_iam_policy.authenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.admin_authenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.authenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.developer_authenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.es_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.log_pusher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.unauthenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.admin_authenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.developer_authenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.unauthenticated](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.admin_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.authenticated_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.developer_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.es_cognito_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.log_pusher_cloudwatch_attach](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_service_linked_role.es](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_service_linked_role) | resource |
| [aws_iam_user.log-pusher](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user) | resource |
| [aws_kms_key.kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_security_group.allow_443](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_iam_policy.amazon_es_cognito_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy) | data source |
| [aws_iam_policy_document.ec2_base_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.ec2_overlay_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.es_vpc_management_access_base](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.es_vpc_management_access_base_overlay](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_vpc.vpc](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/vpc) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_additional_cidr_allow_443"></a> [additional\_cidr\_allow\_443](#input\_additional\_cidr\_allow\_443) | CIDR to allow port 443 communication from | `list(any)` | `[]` | no |
| <a name="input_admin_create_user_only"></a> [admin\_create\_user\_only](#input\_admin\_create\_user\_only) | Only admin can create user (disables the sign up button) | `bool` | `true` | no |
| <a name="input_advanced_options"></a> [advanced\_options](#input\_advanced\_options) | Map of key-value string pairs to specify advanced configuration options. Note that the values for these configuration options must be strings (wrapped in quotes) or they may be wrong and cause a perpetual diff, causing Terraform to want to recreate your Elasticsearch domain on every apply. | `map(string)` | `{}` | no |
| <a name="input_create_access_keys"></a> [create\_access\_keys](#input\_create\_access\_keys) | Boolean to enable creation of iam access keys for the iam users app and backup | `bool` | `true` | no |
| <a name="input_create_iam_service_linked_role"></a> [create\_iam\_service\_linked\_role](#input\_create\_iam\_service\_linked\_role) | Whether to create IAM service linked role for AWS ElasticSearch service. Can be only one per AWS account. | `bool` | `true` | no |
| <a name="input_create_log_pusher_role"></a> [create\_log\_pusher\_role](#input\_create\_log\_pusher\_role) | create a IAM role that has persmission to push logs using the \_bulk API to this elasticsearch | `bool` | `false` | no |
| <a name="input_dedicated_master_threshold"></a> [dedicated\_master\_threshold](#input\_dedicated\_master\_threshold) | The number of instances above which dedicated master nodes will be used. Default: 10 | `number` | `10` | no |
| <a name="input_dedicated_master_type"></a> [dedicated\_master\_type](#input\_dedicated\_master\_type) | ES instance type to be used for dedicated masters (default same as instance\_type) | `string` | `"false"` | no |
| <a name="input_domain_name"></a> [domain\_name](#input\_domain\_name) | Domain name for Elasticsearch cluster | `string` | `"es-domain"` | no |
| <a name="input_domain_prefix"></a> [domain\_prefix](#input\_domain\_prefix) | String to be prefixed to search domain. Default: tf- | `string` | `"tf-"` | no |
| <a name="input_ebs_volume_size"></a> [ebs\_volume\_size](#input\_ebs\_volume\_size) | Optionally use EBS volumes for data storage by specifying volume size in GB (default 0) | `number` | `0` | no |
| <a name="input_ebs_volume_type"></a> [ebs\_volume\_type](#input\_ebs\_volume\_type) | Storage type of EBS volumes, if used (default gp2) | `string` | `"gp2"` | no |
| <a name="input_enable_cognito"></a> [enable\_cognito](#input\_enable\_cognito) | Whether to enable AWS Cognito to handle user access controls to kibana and elasticsearch | `bool` | `false` | no |
| <a name="input_encrypt_at_rest"></a> [encrypt\_at\_rest](#input\_encrypt\_at\_rest) | Enable encrption at rest (only specific instance family types support it: m4, c4, r4, i2, i3 default: false) | `bool` | `false` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `string` | `"ci"` | no |
| <a name="input_es_version"></a> [es\_version](#input\_es\_version) | Version of Elasticsearch to deploy (default 5.1) | `string` | `"5.1"` | no |
| <a name="input_es_zone_awareness"></a> [es\_zone\_awareness](#input\_es\_zone\_awareness) | Enable zone awareness for Elasticsearch cluster (default false) | `bool` | `false` | no |
| <a name="input_force_destroy"></a> [force\_destroy](#input\_force\_destroy) | When destroying this user, destroy even if it has non-Terraform-managed IAM access keys, login profile or MFA devices. Without force\_destroy a user with non-Terraform-managed access keys and login profile will fail to be destroyed. | `bool` | `false` | no |
| <a name="input_instance_count"></a> [instance\_count](#input\_instance\_count) | Number of data nodes in the cluster (default 6) | `number` | `6` | no |
| <a name="input_instance_type"></a> [instance\_type](#input\_instance\_type) | ES instance type for data nodes in the cluster (default t2.small.elasticsearch) | `string` | `"t2.small.elasticsearch"` | no |
| <a name="input_kms_key_id"></a> [kms\_key\_id](#input\_kms\_key\_id) | KMS key used for elasticsearch | `string` | `""` | no |
| <a name="input_log_publishing_options"></a> [log\_publishing\_options](#input\_log\_publishing\_options) | List of maps of options for publishing slow logs to CloudWatch Logs. | `list(map(string))` | `[]` | no |
| <a name="input_log_pusher_additional_policy"></a> [log\_pusher\_additional\_policy](#input\_log\_pusher\_additional\_policy) | Additional policy ARN for log pusher role | `string` | `""` | no |
| <a name="input_log_pusher_iam_roles"></a> [log\_pusher\_iam\_roles](#input\_log\_pusher\_iam\_roles) | List of IAM users or role ARNs from which to permit PUT/POST requests meant to send logs to elasticsearch | `list(string)` | `[]` | no |
| <a name="input_management_iam_roles"></a> [management\_iam\_roles](#input\_management\_iam\_roles) | List of IAM role ARNs from which to permit management traffic (default ['*']).  Note that a client must match both the IP address and the IAM role patterns in order to be permitted access. | `list(string)` | <pre>[<br>  "*"<br>]</pre> | no |
| <a name="input_management_public_ip_addresses"></a> [management\_public\_ip\_addresses](#input\_management\_public\_ip\_addresses) | List of IP addresses from which to permit management traffic (default []).  Note that a client must match both the IP address and the IAM role patterns in order to be permitted access. | `list(string)` | `[]` | no |
| <a name="input_node_to_node_encryption_enabled"></a> [node\_to\_node\_encryption\_enabled](#input\_node\_to\_node\_encryption\_enabled) | Whether to enable node-to-node encryption. | `bool` | `false` | no |
| <a name="input_num_availability_zones"></a> [num\_availability\_zones](#input\_num\_availability\_zones) | Number of availability zones in which to deploy elasticsearch nodes | `number` | `2` | no |
| <a name="input_path"></a> [path](#input\_path) | Desired path for the IAM user | `string` | `"/"` | no |
| <a name="input_permissions_boundary"></a> [permissions\_boundary](#input\_permissions\_boundary) | If provided, all IAM roles will be created with this permissions boundary attached. | `string` | `""` | no |
| <a name="input_pgp_key"></a> [pgp\_key](#input\_pgp\_key) | Either a base-64 encoded PGP public key, or a keybase username in the form keybase:username. Used to encrypt password and access key. | `string` | `""` | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | n/a | `string` | `"es"` | no |
| <a name="input_security_group_ids"></a> [security\_group\_ids](#input\_security\_group\_ids) | List of security groups to apply to the elasticsearch cluster | `list(any)` | `[]` | no |
| <a name="input_snapshot_start_hour"></a> [snapshot\_start\_hour](#input\_snapshot\_start\_hour) | Hour at which automated snapshots are taken, in UTC (default 0) | `number` | `0` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | List of subnets which elasticsearch nodes will be hosted in | `list(any)` | n/a | yes |
| <a name="input_tags"></a> [tags](#input\_tags) | tags to apply to all resources | `map(string)` | `{}` | no |
| <a name="input_use_prefix"></a> [use\_prefix](#input\_use\_prefix) | Flag indicating whether or not to use the domain\_prefix. Default: true | `bool` | `true` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID to import vpc data for use with AWS Elasticsearch | `string` | n/a | yes |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | Name of VPC | `string` | `""` | no |
| <a name="input_warm_count"></a> [warm\_count](#input\_warm\_count) | The number of warm nodes in the cluster. Valid values are between 2 and 150. warm\_count can be only and must be set when warm\_enabled is set to true | `number` | `2` | no |
| <a name="input_warm_enabled"></a> [warm\_enabled](#input\_warm\_enabled) | Indicates whether to enable warm storage | `bool` | `false` | no |
| <a name="input_warm_type"></a> [warm\_type](#input\_warm\_type) | The instance type for the Elasticsearch cluster's warm nodes. Valid values are ultrawarm1.medium.elasticsearch, ultrawarm1.large.elasticsearch | `string` | `"ultrawarm1.medium.elasticsearch"` | no |
| <a name="input_worker_node_role"></a> [worker\_node\_role](#input\_worker\_node\_role) | If you will like eks nodes to assume this role, input the worker node role ARN to allow it to assume the log pusher role | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_IDENTITY_POOL_NAME"></a> [IDENTITY\_POOL\_NAME](#output\_IDENTITY\_POOL\_NAME) | variable to be used in post-apply.sh |
| <a name="output_USER_POOL_ID"></a> [USER\_POOL\_ID](#output\_USER\_POOL\_ID) | variable to be used in post-apply.sh |
| <a name="output_USER_POOL_NAME"></a> [USER\_POOL\_NAME](#output\_USER\_POOL\_NAME) | variable to be used in post-apply.sh |
| <a name="output_app_iam_access_key_id"></a> [app\_iam\_access\_key\_id](#output\_app\_iam\_access\_key\_id) | The access key ID for log pusher |
| <a name="output_app_iam_access_key_secret"></a> [app\_iam\_access\_key\_secret](#output\_app\_iam\_access\_key\_secret) | The access key secret for log pusher |
| <a name="output_app_iam_user_arn"></a> [app\_iam\_user\_arn](#output\_app\_iam\_user\_arn) | The ARN assigned by AWS for log pusher user |
| <a name="output_app_iam_user_name"></a> [app\_iam\_user\_name](#output\_app\_iam\_user\_name) | ES log pusher user's name |
| <a name="output_arn"></a> [arn](#output\_arn) | Amazon Resource Name (ARN) of the domain |
| <a name="output_domain_id"></a> [domain\_id](#output\_domain\_id) | Unique identifier for the domain |
| <a name="output_domain_name"></a> [domain\_name](#output\_domain\_name) | The name of the Elasticsearch domain |
| <a name="output_endpoint"></a> [endpoint](#output\_endpoint) | Domain-specific endpoint used to submit index, search, and data upload requests |
| <a name="output_kibana_endpoint"></a> [kibana\_endpoint](#output\_kibana\_endpoint) | Domain-specific endpoint for kibana without https scheme |
| <a name="output_log_pusher_arn"></a> [log\_pusher\_arn](#output\_log\_pusher\_arn) | ARN of iam role that is allowed to send logs to elasticsearch |
