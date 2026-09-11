# Surveillance and ambient-sensing privacy boundary

Status: **implementation blocked pending product, privacy, security, and Colombian legal review**.

HHM does not currently accept camera or microphone streams, identify people from images or voices, infer activities, record conversations, or retain surveillance media. This is deliberate. Adding an upload endpoint before the controls below exist would create an unsafe collection system without a defensible purpose, consent record, deletion path, or access boundary.

This document is an engineering gate, not legal advice. The review must use current official guidance, including:

- Colombia's [Law 1581 of 2012](https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?country=76&i=49981&offset=0), including its treatment of biometric data as sensitive data and its security and confidentiality principles.
- The SIC's [guidance on personal-data processing through video-surveillance cameras](https://sedeelectronica.sic.gov.co/publicaciones/boletin-juridico/concepto/tratamiento-de-datos-personales-traves-de-camaras-de-videovigilancia).
- The SIC's [personal-data guidance for horizontal property](https://www.sic.gov.co/slider/superindustria-lanza-la-gu%C3%ADa-para-el-tratamiento-de-datos-personales-en-la-propiedad-horizontal).

## Prohibited until the gate is approved

- No camera or microphone in bedrooms, bathrooms, changing areas, or other spaces where a person reasonably expects privacy.
- No continuous or covert ambient conversation recording.
- No facial, voice, gait, or other biometric enrollment or identification.
- No unconstrained model prompt such as “what is this person doing?” and no automated behavioral, safety, employment, tenancy, or access decision.
- No use of residents' or visitors' media for model training, evaluation, demonstrations, or vendor improvement.
- No third-party cloud inference, storage, or support access without a reviewed processor agreement, transfer analysis, and explicit data-flow inventory.
- No weakening or bypassing Shared Auth, HHM product authorization, consent, or retention controls for a “trusted” camera or local network.

## Decisions required before implementation

The accountable HHM owner must approve a written purpose for each sensor and derived signal. “Security,” “analytics,” or “AI” is not specific enough. The review must document necessity, proportionality, the least intrusive alternative, who is affected, who is the data controller and each processor, and how a person exercises access, correction, deletion, and complaint rights.

The approved design must include:

1. A data inventory covering raw video, raw audio, thumbnails, transcripts, embeddings, identity matches, activity labels, confidence scores, metadata, audit logs, backups, and vendor copies.
2. A prominently communicated privacy notice and physical signage before a person enters a monitored zone, plus a versioned evidence trail for any required authorization or consent.
3. A practical non-biometric alternative for entry and participation. Refusal or withdrawal must not silently deny housing or essential access.
4. A separate, affirmative, time-bounded interaction for conversation recording. Visible recording state, participant notice, a hardware or equally reliable stop control, and withdrawal/deletion handling are mandatory. General house terms are not sufficient engineering evidence of consent.
5. A zone map and field-of-view review. Privacy masks must be applied at the edge before upload; microphones are disabled by default.
6. A written retention schedule for every data class and purpose. Expiry must be technically enforced in primary storage, search indexes, embeddings, caches, and backups, with deletion evidence. “Keep indefinitely in case it is useful” is prohibited.
7. A documented response for children, workers, contractors, guests, household staff, deliveries, and people unable to use the ordinary consent flow.
8. A human-review and appeal process for every identity or activity inference. Low-confidence, conflicting, or missing results must fail safely and may not become an adverse automated decision.
9. A security and privacy impact assessment, threat model, incident playbook, vendor review, and final approval recorded before the feature flag can be enabled.

## Required technical architecture

If approved, capture should terminate at a separately administered edge gateway rather than the general HHM API. The gateway must have a unique, revocable device identity, secure boot and update policy, encrypted local spool, clock-health signal, privacy masks, visible capture status, and hardware-backed key storage where supported.

The ingestion plane must be isolated from resident and visitor application traffic. Each bounded media chunk needs mutually authenticated transport, a device signature, sequence number, timestamp, content digest, declared media type, duration, and strict maximum size. The service must reject replays, clock anomalies, malformed codecs, decompression bombs, unknown devices, and over-quota streams before durable storage.

Raw media should be encrypted with per-site or per-camera envelope keys and placed in quarantine object storage. The operational database should contain opaque object references and minimal metadata, not media blobs. Playback must use short-lived, single-purpose grants. Decryption, export, recognition, transcript access, and deletion each require separate HHM-owned permissions and tamper-evident audit events.

Inference must run in an isolated worker with an explicit model/version/purpose allowlist. Derived events must preserve confidence and provenance, expire with or before their source material, and never be treated as verified identity or fact without the approved review step. Face and voice templates require their own encrypted store, enrollment lifecycle, revocation, and false-match testing across the population actually affected.

Operational telemetry must be payload-free. Logs, traces, metrics, crash dumps, support bundles, and alerts may contain opaque camera, site, request, and event identifiers, but never image bytes, audio, transcripts, names, biometric templates, authorization tokens, signed media URLs, or model prompts containing personal data.

## Authorization boundary

Shared Auth establishes the authenticated principal; it does not decide whether that principal may administer cameras, view live video, retrieve recordings, enroll identities, run inference, export evidence, or delete data. HHM must implement those as separate product permissions bound to verified `(provider, tenant, subject)` identities and the relevant house/site.

Device authentication is also not human authorization. A valid camera certificate permits only bounded ingestion for its configured site and stream. It must never grant viewing or administrative access.

Production access requires least privilege, short sessions, stronger assurance for sensitive actions, immediate revocation, and dual approval for bulk export or biometric enrollment. Every access outcome must be auditable without logging the media itself.

## Minimum verification before release

- Unit and integration tests for replay rejection, signature failure, wrong-site isolation, expired grants, body and duration limits, unsupported media, consent withdrawal, retention deletion, and fail-closed auth degradation.
- Adversarial tests for stolen device credentials, object-reference guessing, signed-URL leakage, malformed media, inference prompt injection, model exfiltration, log leakage, and operator privilege escalation.
- Measured false-positive and false-negative behavior with an explicit “unknown” path; identity or behavior guesses must not be forced.
- A deletion drill proving removal from primary storage, derived stores, indexes, and scheduled backups.
- A breach-response exercise and a physical inspection confirming actual camera fields of view and microphone state.
- A named owner, expiry date, and rollback procedure for every production feature flag.

Until these gates are met and approved, camera and audio configuration in HHM must remain absent or disabled, and the API must continue to expose no surveillance-ingestion route.
