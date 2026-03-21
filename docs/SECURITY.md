# Security Considerations

## Secrets Management
- Use HashiCorp Vault for all credentials
- Never commit secrets to git
- Rotate API keys regularly

## Network Security
- All services on isolated Docker network
- TLS for external communications
- Firewall rules for production

## Authentication
- JWT tokens with 30-minute expiry
- bcrypt password hashing
- Role-based access control (RBAC)

## Compliance
- Audit logging for all actions
- Data retention policies
- GDPR considerations for EU deployments
