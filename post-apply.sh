#!/bin/bash

IFS=

which jq 2>&1 >/dev/null || (
  echo "jq not available, please install jq first"
  exit 1
)
which aws 2>&1 >/dev/null || (
  echo "aws-cli not available, please install aws first"
  exit 1
)

trim() {
    local var="$*"
    # remove leading whitespace characters
    var="${var#"${var%%[![:space:]]*}"}"
    # remove trailing whitespace characters
    var="${var%"${var##*[![:space:]]}"}"
    echo -n "$var"
}


TF_OUTPUT=$(terragrunt output) # Intended to be used with terragrunt, if you are using terraform instead, change this

IDENTITY_POOL_NAME=$(trim "$(echo $TF_OUTPUT | grep IDENTITY_POOL_NAME | cut -d= -f2)")
USER_POOL_NAME=$(trim "$(echo $TF_OUTPUT | grep USER_POOL_NAME | cut -d= -f2)")

USER_POOL_CLIENT_PREFIX="AWSElasticsearch-"
USER_POOL_ID_PROVIDER="COGNITO"

echo "+++ Preparing to update Cognito App Client"
IDENTITY_POOL_ID=$(aws cognito-identity list-identity-pools --max-results 25 | jq -r '.IdentityPools[] | select(.IdentityPoolName == "'"${IDENTITY_POOL_NAME}"'") | .IdentityPoolId')
USER_POOL_ID=$(aws cognito-idp list-user-pools --max-results 25 | jq -r '.UserPools[] | select(.Name=="'"${USER_POOL_NAME}"'") | .Id')
CLIENT_ID=$(aws cognito-idp list-user-pool-clients --user-pool-id "${USER_POOL_ID}" --max-results 25 | jq -r '.UserPoolClients[] | select(.ClientName | contains("'"${USER_POOL_CLIENT_PREFIX}"'")) | .ClientId')

aws cognito-idp describe-user-pool-client --user-pool-id "${USER_POOL_ID}" --client-id "${CLIENT_ID}"

UPDATE_JSON=$(aws cognito-idp describe-user-pool-client --user-pool-id "${USER_POOL_ID}" --client-id "${CLIENT_ID}" | \
jq '.UserPoolClient.SupportedIdentityProviders=["'${USER_POOL_ID_PROVIDER}'"] |
    .UserPoolClient |
    del(.ClientSecret) |
    del(.CreationDate) |
    del(.LastModifiedDate)')

echo "+++ Updating Cognito App Client"
aws cognito-idp update-user-pool-client --user-pool-id "${USER_POOL_ID}" --client-id "${CLIENT_ID}" --cli-input-json "${UPDATE_JSON}"

echo "+++ Preparing to update Identity Pool Role Mappings"
IDENTITY_PROVIDER="cognito-idp.ap-southeast-1.amazonaws.com/$USER_POOL_ID:$CLIENT_ID"
ROLES=$(aws cognito-identity get-identity-pool-roles --identity-pool-id ${IDENTITY_POOL_ID} | jq .'Roles')
UPDATE_JSON=$(cat <<EOF
{
  "RoleMappings":
    {
      "$IDENTITY_PROVIDER": {
        "Type": "Token",
        "AmbiguousRoleResolution": "Deny"
      }
    }
  ,
  "Roles": $ROLES
}
EOF
)
echo $UPDATE_JSON

echo "+++ Updating Identity Pool Role Mappings"
aws cognito-identity set-identity-pool-roles --identity-pool-id ${IDENTITY_POOL_ID} --cli-input-json "${UPDATE_JSON}"