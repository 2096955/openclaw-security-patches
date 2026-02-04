# OpenClaw Security Patches

Security hardening patches for OpenClaw gateway deployments.

## What's Included

- **IAP Authentication**: Google Cloud Identity-Aware Proxy JWT validation
- **Service Account OIDC**: GCP service account token validation
- **Rate Limiting**: Sliding-window throttling for failed auth attempts
- **Security Documentation**: Trust boundaries, replay protection, credential rotation guides

## Quick Start

```bash
# Clone OpenClaw at the target version
git clone https://github.com/openclaw/openclaw.git
cd openclaw
git checkout v2026.2.2

# Download and apply the security patch
curl -fsSL https://raw.githubusercontent.com/2096955/openclaw-security-patches/main/patches/security-v2026.2.2.patch -o security.patch
git apply --3way security.patch

# Install and build
pnpm install
pnpm build
```

## Patch Contents

| File | Purpose |
|------|---------|
| `src/gateway/auth-iap.ts` | IAP and Service Account JWT validation |
| `src/gateway/auth-rate-limit.ts` | Sliding-window rate limiter |
| `src/gateway/auth.ts` | Auth chain integration |
| `src/config/types.gateway.ts` | IAP/ServiceAccount config types |
| `src/config/zod-schema.ts` | Config validation schemas |
| `docs/gateway/security/index.md` | Security documentation |

## Verification

```bash
# Verify checksum before applying
curl -fsSL https://raw.githubusercontent.com/2096955/openclaw-security-patches/main/patches/checksums.sha256 -o checksums.sha256
sha256sum -c checksums.sha256  # Linux
# or: shasum -a 256 -c checksums.sha256  # macOS
```

## Base Version

These patches are built against OpenClaw `v2026.2.2`. Check `patches/METADATA.json` for exact commit SHA.

## License

Same license as OpenClaw (see upstream repository).
