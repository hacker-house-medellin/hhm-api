# hhm-api

Axum REST and WebSocket API server for Hacker House Medellín.

**Product:** Hacker House Medellín — Operations software for an entrepreneur coliving and coworking community.

Run rooms, desks, member stays, community events, access workflows, and day-to-day operations for a hacker house in Medellín, Colombia.

## Safety and production boundary

The bootstrap does not implement payments, identity verification, door-control hardware, or Colombian lodging compliance. Add those only after security and local regulatory review.

This repository is an executable bootstrap, not a production deployment. Before live
use, add authentication, tenant authorization, rate limits, durable migrations,
observability, backups, incident response, dependency review, and secret management.
## Routes

- `GET /healthz`, `GET /readyz`, `GET /metrics`
- `GET|POST /api/v1/reservations`
- `GET /api/v1/reservations/{id}`
- `GET /ws` for JSON event envelopes

The bootstrap uses bounded in-memory state so transport behavior is immediately
testable. Replace it with SeaORM/PostgreSQL transactions before production and keep
`hhm-interfaces` as the tagged wire-contract authority.

```bash
cargo run
```
