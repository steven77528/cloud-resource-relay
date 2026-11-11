# Project Maintenance

- This directory is the canonical, independently deployable collection relay.
  The user explicitly authorized this sibling project. Make future relay changes
  here; do not create release copies or update ZIPs.
- The sibling cloud-resource-monitor project owns provider parsing, pagination,
  metric calculations, storage and alerts. It is not a relay runtime dependency.
  Keep only required forwarding validation, authentication and signing code here.
- Preserve real credentials, client grants and account/operation enablement
  unless the user requests a change. Never print secrets from local config,
  environment files, token files, private keys or upstream responses.
- Keep provider credentials and business tokens exclusively on the trusted
  relay. Forward only explicitly authorized upstream requests and their raw
  vendor JSON responses; do not generate metrics or implement monitoring here.
- Monitor-to-relay traffic uses HTTP over an explicit IP and port on a trusted
  network, as requested by the user; it does not require a domain or certificate.
  Preserve verified TLS for vendor requests and for optional HTTPS relay mode.
  Require explicit client operation/resource grants and exact request identity.
  Validate unsigned URLs, methods and bodies against the
  built-in read-only API catalog; do not accept arbitrary headers or endpoints.
- Keep provider operations read-only. Never initiate payment, refund,
  settlement, signing or other business mutations.
- Run offline checks by default. Use temporary credentials for local HTTP
  integration and temporary certificates only for optional HTTPS regression
  checks. Simulate upstream provider responses and never install test CAs globally.
- Do not send notifications, start a production monitor scheduler, or connect
  to a business database during verification. The relay has no MySQL dependency.
- Update the Chinese README and example configuration when behavior or
  deployment changes. Keep all examples synthetic and disabled by default.
