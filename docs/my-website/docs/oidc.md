# OIDC

| Provider | Secret format | Notes |
| --- | --- | --- |
| AWS | `oidc/aws/<audience>` | Mints a JWT with AWS STS `GetWebIdentityToken` |

## Azure with AWS IAM Outbound Identity Federation

Use the Azure token exchange audience when federating an AWS IAM role into Entra ID:

```yaml
litellm_params:
  azure_ad_token: oidc/aws/api://AzureADTokenExchange
```

When configuring the Entra federated credential, set the subject to the IAM role ARN, not the `assumed-role/...` session ARN. Entra federated credentials also require RS256-signed JWTs.
