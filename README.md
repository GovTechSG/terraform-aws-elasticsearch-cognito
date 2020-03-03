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

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| additional\_cidr\_allow\_443 | CIDR to allow port 443 communication from | list | `<list>` | no |
| advanced\_options | Map of key-value string pairs to specify advanced configuration options. Note that the values for these configuration options must be strings (wrapped in quotes) or they may be wrong and cause a perpetual diff, causing Terraform to want to recreate your Elasticsearch domain on every apply. | map(string) | `<map>` | no |
| create\_access\_keys | Boolean to enable creation of iam access keys for the iam users app and backup | bool | `"true"` | no |
| create\_iam\_service\_linked\_role | Whether to create IAM service linked role for AWS ElasticSearch service. Can be only one per AWS account. | bool | `"true"` | no |
| create\_log\_pusher\_role | create a IAM role that has persmission to push logs using the _bulk API to this elasticsearch | bool | `"false"` | no |
| dedicated\_master\_threshold | The number of instances above which dedicated master nodes will be used. Default: 10 | number | `"10"` | no |
| dedicated\_master\_type | ES instance type to be used for dedicated masters (default same as instance_type) | string | `"false"` | no |
| domain\_name | Domain name for Elasticsearch cluster | string | `"es-domain"` | no |
| domain\_prefix | String to be prefixed to search domain. Default: tf- | string | `"tf-"` | no |
| ebs\_volume\_size | Optionally use EBS volumes for data storage by specifying volume size in GB (default 0) | number | `"0"` | no |
| ebs\_volume\_type | Storage type of EBS volumes, if used (default gp2) | string | `"gp2"` | no |
| enable\_cognito | Whether to enable AWS Cognito to handle user access controls to kibana and elasticsearch | bool | `"false"` | no |
| encrypt\_at\_rest | Enable encrption at rest (only specific instance family types support it: m4, c4, r4, i2, i3 default: false) | bool | `"false"` | no |
| es\_version | Version of Elasticsearch to deploy (default 5.1) | string | `"5.1"` | no |
| es\_zone\_awareness | Enable zone awareness for Elasticsearch cluster (default false) | bool | `"false"` | no |
| force\_destroy | When destroying this user, destroy even if it has non-Terraform-managed IAM access keys, login profile or MFA devices. Without force_destroy a user with non-Terraform-managed access keys and login profile will fail to be destroyed. | bool | `"false"` | no |
| instance\_count | Number of data nodes in the cluster (default 6) | number | `"6"` | no |
| instance\_type | ES instance type for data nodes in the cluster (default t2.small.elasticsearch) | string | `"t2.small.elasticsearch"` | no |
| kms\_key\_id | KMS key used for elasticsearch | string | `""` | no |
| log\_publishing\_options | List of maps of options for publishing slow logs to CloudWatch Logs. | list(map(string)) | `<list>` | no |
| log\_pusher\_iam\_roles | List of IAM users or role ARNs from which to permit PUT/POST requests meant to send logs to elasticsearch | list(string) | `<list>` | no |
| management\_iam\_roles | List of IAM role ARNs from which to permit management traffic (default ['*']).  Note that a client must match both the IP address and the IAM role patterns in order to be permitted access. | list(string) | `<list>` | no |
| management\_public\_ip\_addresses | List of IP addresses from which to permit management traffic (default []).  Note that a client must match both the IP address and the IAM role patterns in order to be permitted access. | list(string) | `<list>` | no |
| node\_to\_node\_encryption\_enabled | Whether to enable node-to-node encryption. | bool | `"false"` | no |
| num\_availability\_zones | Number of availability zones in which to deploy elasticsearch nodes | number | `"2"` | no |
| path | Desired path for the IAM user | string | `"/"` | no |
| permissions\_boundary | The ARN of the policy that is used to set the permissions boundary for the user. | string | `""` | no |
| permissions\_boundary | If provided, all IAM roles will be created with this permissions boundary attached. | string | `""` | no |
| pgp\_key | Either a base-64 encoded PGP public key, or a keybase username in the form keybase:username. Used to encrypt password and access key. | string | `""` | no |
| security\_group\_ids | List of security groups to apply to the elasticsearch cluster | list | `<list>` | no |
| snapshot\_start\_hour | Hour at which automated snapshots are taken, in UTC (default 0) | number | `"0"` | no |
| subnet\_ids | List of subnets which elasticsearch nodes will be hosted in | list | n/a | yes |
| tags | tags to apply to all resources | map(string) | `<map>` | no |
| use\_prefix | Flag indicating whether or not to use the domain_prefix. Default: true | bool | `"true"` | no |
| vpc\_id | VPC ID to import vpc data for use with AWS Elasticsearch | string | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| IDENTITY\_POOL\_NAME | variable to be used in post-apply.sh |
| USER\_POOL\_ID | variable to be used in post-apply.sh |
| USER\_POOL\_NAME | variable to be used in post-apply.sh |
| arn | Amazon Resource Name (ARN) of the domain |
| domain\_id | Unique identifier for the domain |
| domain\_name | The name of the Elasticsearch domain |
| endpoint | Domain-specific endpoint used to submit index, search, and data upload requests |
| kibana\_endpoint | Domain-specific endpoint for kibana without https scheme |
| log\_pusher\_arn | ARN of iam role that is allowed to send logs to elasticsearch |