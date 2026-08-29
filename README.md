# hhm-api

**Hacker House Medellín — Rust REST and WebSocket API server**

Operations and community software for an entrepreneur-focused coliving and coworking house in Medellín, Colombia.

This repository is an independently deployable component and a member of the `hhm-monorepo` workspace.

## Baseline

- Rust 2024 edition.
- Axum HTTP and WebSocket transport.
- SeaORM/PostgreSQL connection through `DATABASE_URL`.
- Dual Shared Auth and Supabase authentication through the official `shared-auth-lib` guard, pinned to an immutable revision.
- Structured operational events through `oresoftware-next-loggers`, pinned to an immutable `ores-otel` revision.
- Managed-doorway and P2P contracts from `hhm-interfaces`, pinned to immutable commit `ffc1df71d1d89202b431f4830cc2a43e4a451da3`.
- Docker and GitHub Actions entry points.
- Contracts live in `hhm-interfaces`; shared behavior belongs in `hhm-libs`.

## Implemented routes

- `GET /healthz`
- `GET /v1/reservations`
- `POST /v1/reservations`
- `GET /v1/reservations/{id}`
- `POST /v1/visitor-qr/{check-in|check-out}`
- `POST /v1/visits/check-in`
- `POST /v1/visits/check-out`
- `GET /v1/ws`

The current reservation store is process-local. Its routes and WebSocket are disabled by default; `ALLOW_UNAUTHENTICATED_DEMO_RESERVATIONS=true` enables them only for explicit local scaffolding. The in-memory store is capped at 10,000 records. A configured database connection is reported by `/healthz`, but persistence and migrations remain a separate delivery gate.
All request bodies are limited to 64 KiB.

## Reservation boundary

Creation accepts a JSON object with:

- `member_name`
- `room_type`
- `check_in`
- `check_out`
- `workspace_plan`
- `status`
- `notes`

Text fields are trimmed and bounded. `check_out` must be later than `check_in`, a stay may not exceed 366 days, and status must be one of `pending`, `confirmed`, `checked_in`, `checked_out`, or `cancelled`. Invalid input receives a typed `422` response.

Successful creation broadcasts a typed `reservation.created` envelope. Lagged WebSocket consumers skip dropped broadcast items and continue receiving subsequent events.

## Visitor access boundary

`POST /v1/visitor-qr/{action}` issues a QR payload for an allowlisted door. It requires authentication through either Shared Auth or Supabase and then applies HHM-owned product authorization using an exact verified `(provider, tenant, subject)` tuple from `HHM_QR_ISSUER_IDENTITIES`. Email addresses and Shared Auth roles are deliberately not authorization inputs. If both authentication authorities are unavailable, issuance fails with `503` instead of silently allowing access.

The QR token is:

- signed with HMAC-SHA-256 using `VISITOR_QR_SIGNING_KEY`;
- bound to the `hhm-visitor-access` audience, door, and `check-in` or `check-out` action;
- rotated on every UTC minute boundary, with a 15-second scan grace period;
- bounded and compared in constant time;
- rate-limited to 128 successful redemptions per door/action/minute token.

Check-in requires the exact current `VISITOR_PRIVACY_NOTICE_VERSION`, records only a bounded display name, and returns a private checkout receipt. Check-out requires a current exit QR, the visit ID, and that private receipt. The receipt is stored only as an HMAC tag, and the display name is erased on checkout. Operational logs contain event type, outcome, and bounded door ID only—never names, tokens, receipts, or authentication credentials.

Visitor records and QR redemption counters are currently process-local. Restarting the API loses them, and multiple replicas do not share them. `/healthz` reports `visitor_state_durable: false`; production deployment is blocked until the state and atomic redemption limits are moved to a durable shared store.

## Managed-doorway admission foundation

`src/presence.rs` implements a transport-independent, fail-closed admission engine for the canonical `hhm.doorway-observation.v1` contract. It keeps the verified `(provider, tenant, subject)` principal, HHM product authorization, registered-key and attestation verification, nonce binding, replay detection, and monotonic presence sequence as separate checks. Nonces are bound server-side to the exact principal and house. A successful atomic commit consumes the submission nonce, door challenge, and independent corroboration evidence; identical retries return the original decision, while conflicting reuse is rejected.

The engine treats verifier or authorization availability failures separately from invalid evidence, rejects stale previous sequences, and converts ambiguous or contradictory direction evidence to `confirmation_required`. Bluetooth proximity, RSSI, device names, OS pairing, and client assertions cannot create an accepted transition.

This foundation is covered by positive, replay, idempotency, concurrent-duplicate, direction, authorization, verifier-unavailable, and sequence-conflict tests. It is not wired to HTTP acceptance: the current in-memory ledger and test verifier/authorizer are not production adapters. The OpenAPI presence routes remain unavailable until PostgreSQL-backed atomic replay/ledger state, registered beacon and corroborator key verification, official Shared Auth-bound device attestation, HHM resident/device/door authorization, key revocation, rate limiting, and privacy operations are configured together.

## Dual-auth configuration

The visitor QR feature is fail-closed: either all dual-auth variables are supplied or none are. Required variables are `SHARED_AUTH_BASE_URL`, `SHARED_AUTH_ISSUER`, `SHARED_AUTH_AUDIENCE`, `AUTH_INTROSPECT_SECRET`, `SUPABASE_URL`, `SUPABASE_PROJECT_REF`, `SUPABASE_ANON_KEY`, and `HHM_QR_ISSUER_IDENTITIES`. Remote authority URLs must use HTTPS; plaintext HTTP is accepted only for loopback development.

The visitor QR service similarly requires all of `VISITOR_QR_SIGNING_KEY`, `VISITOR_DOOR_IDS`, and `VISITOR_PRIVACY_NOTICE_VERSION`. The signing key must be unpadded base64url decoding to 32–64 bytes. Keep all credentials in the encrypted environment workflow described below.

## CORS

`CORS_ORIGINS` is a comma-separated list of exact `http` or `https` origins. Wildcards, paths, and query strings are rejected at startup. Leaving it empty allows same-origin use while emitting no cross-origin allow header.

Example:

```dotenv
CORS_ORIGINS=http://localhost:3000,https://app.example.test
```

## Development

```bash
cp .env.example .env
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

## Deployment boundary

Durable reservation, visitor, and presence persistence; migrations; tenant isolation and product authorization for reservation routes; distributed rate limiting; key rotation; production secret provisioning; and an end-to-end authorization review must be completed before deployment. The reservation endpoints and WebSocket are unauthenticated scaffolding and therefore fail closed unless the local-only demo flag is explicitly enabled. Presence acceptance is not routed at all until its real adapters exist. Do not expose this service to an untrusted network or treat its process-local state as a production booking or physical-access system.

Camera, microphone, facial-recognition, conversation-recording, and activity-inference ingestion are intentionally not implemented in this service. Those features require the privacy, consent, zoning, retention, encryption, access-control, and human-review gates in [`docs/surveillance-privacy-boundary.md`](docs/surveillance-privacy-boundary.md) before implementation.

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).
