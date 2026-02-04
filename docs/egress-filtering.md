# Egress filtering and network segmentation (scaffold)

**Plan item N.** A compromised gateway can make arbitrary outbound connections.

## Intended design (e.g. GCP Phase 2)

- Use VPC firewall rules to restrict egress to known endpoints.
- Proxy all outbound HTTP through a controlled gateway with logging.
- Block direct egress to the internet from sensitive workloads; require NAT/proxy.

## Status

Placeholder; not implemented. See security audit plan item N.
