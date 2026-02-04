# OpenClaw Security Patches

Security hardening patches and documentation for OpenClaw gateway deployments.

## Overview

This repository contains production-grade security enhancements for OpenClaw, including:

- Identity-Aware Proxy (IAP) integration for GCP deployments
- Service Account OIDC validation
- Failed authentication rate limiting
- Replay protection mechanisms
- Session binding
- Credential rotation strategies
- Content Security Policy (CSP) and Subresource Integrity (SRI)
- Egress filtering
- Kill switch implementation
- Trust boundary documentation

## What's Included

### Authentication & Authorization
- **IAP Integration**: Google Cloud Identity-Aware Proxy validation
- **Service Account OIDC**: Validate service-to-service authentication
- **Rate Limiting**: Failed authentication attempt throttling
- **Replay Protection**: Prevent replay attacks on authentication flows

### Security Hardening
- **Session Binding**: Cryptographic session binding to prevent session hijacking
- **Credential Rotation**: Automated credential rotation strategies
- **Kill Switch**: Emergency shutdown mechanisms
- **Egress Filtering**: Control outbound network traffic

### Frontend Security
- **CSP/SRI**: Content Security Policy and Subresource Integrity implementation
- **Trust Boundaries**: Documentation of system trust boundaries and data flow

## Repository Structure

```
docs/security/          # Security documentation
  ├── credential-rotation.md
  ├── csp-sri.md
  ├── egress-filtering.md
  ├── kill-switch.md
  ├── phase-2-gcp-hardening.md
  ├── replay-protection.md
  ├── session-binding.md
  └── trust-boundaries.md

src/gateway/            # Gateway security implementations
  ├── auth-iap.ts              # IAP authentication
  ├── auth-iap.test.ts
  ├── auth-rate-limit.ts       # Rate limiting
  └── auth.ts                   # Core auth logic

src/config/             # Security configuration
  ├── types.gateway.ts
  ├── zod-schema.ts
  └── config.gateway-iap-audience.test.ts

audits/                 # Security audit reports
  ├── SECURITY_AUDIT_REVIEW.md
  └── SECURITY_AUDIT_CURSOR_REVIEW.md
```

## Apply Patches

These patches are designed to be applied against a specific OpenClaw release version.

### Prerequisites
- Clean OpenClaw clone at the target version
- Git

### Application Steps

1. **Checkout base version**:
   ```bash
   git checkout v2026.2.0  # or your target version
   ```

2. **Apply security patch**:
   ```bash
   git apply --3way patches/security-v2026.2.0.patch
   ```

3. **Resolve conflicts** (if any):
   ```bash
   git status
   # Fix conflicts, then:
   git add .
   ```

4. **Verify implementation**:
   ```bash
   pnpm test
   pnpm check
   ```

## Configuration

After applying patches, configure security features in your OpenClaw config:

```typescript
{
  gateway: {
    auth: {
      iap: {
        enabled: true,
        audience: "/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID"
      },
      rateLimit: {
        enabled: true,
        maxFailedAttempts: 5,
        windowMs: 900000  // 15 minutes
      }
    }
  }
}
```

## GCP IAP Setup

1. Enable Identity-Aware Proxy in GCP Console
2. Configure OAuth consent screen
3. Add authorized users/groups
4. Set IAP audience in OpenClaw config
5. Deploy with service account credentials

See `docs/security/phase-2-gcp-hardening.md` for detailed GCP setup.

## Security Considerations

- **Production Deployment**: These patches implement defense-in-depth strategies
- **Compliance**: Audit logs, replay protection, and session binding help meet regulatory requirements
- **Performance**: Rate limiting and session validation add minimal latency (<5ms)
- **Monitoring**: Enable security event logging for incident response

## Testing

Security implementations include comprehensive test coverage:

```bash
# Run security tests
pnpm test auth-iap
pnpm test auth-rate-limit
pnpm test auth

# Run full test suite
pnpm test
```

## Contributing

Security patches follow responsible disclosure:

1. Report vulnerabilities privately
2. Allow 90 days for patch development
3. Coordinate disclosure timing

## License

Same as OpenClaw main repository.

## Support

For security concerns or implementation questions, open an issue or contact the maintainers directly.

---

**Warning**: These patches modify authentication and authorization logic. Test thoroughly in staging before production deployment.
