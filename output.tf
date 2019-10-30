output "arn" {
  description = "Amazon Resource Name (ARN) of the domain"
  value       = aws_elasticsearch_domain.es_vpc.arn
}

output "domain_id" {
  description = "Unique identifier for the domain"
  value       = aws_elasticsearch_domain.es_vpc.domain_id
}

output "domain_name" {
  description = "The name of the Elasticsearch domain"
  value       = aws_elasticsearch_domain.es_vpc.domain_name
}

output "endpoint" {
  description = "Domain-specific endpoint used to submit index, search, and data upload requests"
  value       = aws_elasticsearch_domain.es_vpc.endpoint
}

output "kibana_endpoint" {
  description = "Domain-specific endpoint for kibana without https scheme"
  value       = aws_elasticsearch_domain.es_vpc.kibana_endpoint
}

output "USER_POOL_ID" {
  description = "variable to be used in post-apply.sh"
  value       = var.enable_cognito ? aws_cognito_user_pool.kibana[0].id : ""
}

output "IDENTITY_POOL_NAME" {
  description = "variable to be used in post-apply.sh"
  value       = var.enable_cognito ? local.identity_pool_name : ""
}

output "USER_POOL_NAME" {
  description = "variable to be used in post-apply.sh"
  value       = var.enable_cognito ? aws_cognito_user_pool.kibana[0].name : ""
}

output "log_pusher_arn" {
  description = "ARN of iam role that is allowed to send logs to elasticsearch"
  value       = aws_iam_role.log_pusher[0].arn
}