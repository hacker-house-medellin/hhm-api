use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use chrono::{DateTime, Duration, Utc};
use hhm_interfaces::{
    DoorwayObservation, PRESENCE_AUDIENCE, PRESENCE_DECISION_SCHEMA,
    PRESENCE_SUBMISSION_NONCE_SCHEMA, PresenceDecision, PresenceDecisionKind,
    PresenceDecisionReason, PresenceSubmissionNonce, PresenceSubmissionNonceRequest,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

const MAX_PENDING_NONCES: usize = 10_000;
const MAX_RECORDED_OBSERVATIONS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PresencePrincipal {
    provider: String,
    tenant: String,
    subject: String,
}

impl PresencePrincipal {
    pub fn from_verified_identity(
        provider: &str,
        tenant: &str,
        subject: &str,
    ) -> Result<Self, AdmissionError> {
        if !valid_identity_component(provider, 64)
            || !valid_identity_component(tenant, 255)
            || !valid_identity_component(subject, 512)
        {
            return Err(AdmissionError::InvalidRequest);
        }
        Ok(Self {
            provider: provider.to_owned(),
            tenant: tenant.to_owned(),
            subject: subject.to_owned(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Verified,
    Invalid,
    Unavailable,
    DeviceRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductAuthorization {
    Allowed,
    Denied,
    Unavailable,
}

pub trait PresenceEvidenceVerifier: Send + Sync {
    /// Verifies registered beacon, independent corroborator, enrolled-device,
    /// attestation, signature, audience, and principal/device bindings.
    fn verify(
        &self,
        principal: &PresencePrincipal,
        observation: &DoorwayObservation,
        now: DateTime<Utc>,
    ) -> Verification;
}

pub trait PresenceAuthorizer: Send + Sync {
    /// HHM product authorization; authentication success alone is insufficient.
    fn authorize_nonce(
        &self,
        principal: &PresencePrincipal,
        house_id: &str,
    ) -> ProductAuthorization;

    fn authorize_observation(
        &self,
        principal: &PresencePrincipal,
        observation: &DoorwayObservation,
    ) -> ProductAuthorization;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidRequest,
    AuthenticationUnavailable,
    DeviceRevoked,
    EvidenceInvalid,
    Expired,
    MembershipDenied,
    PolicyConflict,
    RateLimited,
    Replayed,
}

#[derive(Clone)]
pub struct PresenceAdmission<V, A> {
    verifier: Arc<V>,
    authorizer: Arc<A>,
    ledger: Arc<Mutex<PresenceLedger>>,
}

#[derive(Default)]
struct PresenceLedger {
    nonces: HashMap<String, NonceGrant>,
    used_challenges: HashSet<Uuid>,
    used_evidence: HashSet<Uuid>,
    sequences: HashMap<(PresencePrincipal, String), u64>,
    decisions: HashMap<Uuid, RecordedDecision>,
}

struct NonceGrant {
    principal: PresencePrincipal,
    house_id: String,
    expires_at: DateTime<Utc>,
}

struct RecordedDecision {
    request_digest: [u8; 32],
    decision: PresenceDecision,
}

impl<V, A> PresenceAdmission<V, A>
where
    V: PresenceEvidenceVerifier,
    A: PresenceAuthorizer,
{
    pub fn new(verifier: Arc<V>, authorizer: Arc<A>) -> Self {
        Self {
            verifier,
            authorizer,
            ledger: Arc::new(Mutex::new(PresenceLedger::default())),
        }
    }

    pub async fn issue_nonce(
        &self,
        principal: &PresencePrincipal,
        request: &PresenceSubmissionNonceRequest,
        now: DateTime<Utc>,
    ) -> Result<PresenceSubmissionNonce, AdmissionError> {
        request
            .validate_shape()
            .map_err(|_| AdmissionError::InvalidRequest)?;
        match self
            .authorizer
            .authorize_nonce(principal, &request.house_id)
        {
            ProductAuthorization::Allowed => {}
            ProductAuthorization::Denied => return Err(AdmissionError::MembershipDenied),
            ProductAuthorization::Unavailable => {
                return Err(AdmissionError::AuthenticationUnavailable);
            }
        }

        let expires_at = now + Duration::seconds(60);
        let nonce = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let mut ledger = self.ledger.lock().await;
        ledger.nonces.retain(|_, grant| grant.expires_at > now);
        if ledger.nonces.len() >= MAX_PENDING_NONCES {
            return Err(AdmissionError::RateLimited);
        }
        ledger.nonces.insert(
            nonce.clone(),
            NonceGrant {
                principal: principal.clone(),
                house_id: request.house_id.clone(),
                expires_at,
            },
        );
        Ok(PresenceSubmissionNonce {
            schema: PRESENCE_SUBMISSION_NONCE_SCHEMA.into(),
            audience: PRESENCE_AUDIENCE.into(),
            nonce,
            expires_at,
        })
    }

    pub async fn submit(
        &self,
        principal: &PresencePrincipal,
        observation: &DoorwayObservation,
        now: DateTime<Utc>,
    ) -> Result<PresenceDecision, AdmissionError> {
        observation
            .validate_shape(now)
            .map_err(|_| AdmissionError::EvidenceInvalid)?;
        let request_digest = observation_digest(observation)?;

        {
            let ledger = self.ledger.lock().await;
            if let Some(recorded) = ledger.decisions.get(&observation.observation_id) {
                return if recorded.request_digest == request_digest {
                    Ok(recorded.decision.clone())
                } else {
                    Err(AdmissionError::Replayed)
                };
            }
        }

        match self
            .authorizer
            .authorize_observation(principal, observation)
        {
            ProductAuthorization::Allowed => {}
            ProductAuthorization::Denied => return Err(AdmissionError::MembershipDenied),
            ProductAuthorization::Unavailable => {
                return Err(AdmissionError::AuthenticationUnavailable);
            }
        }
        match self.verifier.verify(principal, observation, now) {
            Verification::Verified => {}
            Verification::Invalid => return Err(AdmissionError::EvidenceInvalid),
            Verification::Unavailable => {
                return Err(AdmissionError::AuthenticationUnavailable);
            }
            Verification::DeviceRevoked => return Err(AdmissionError::DeviceRevoked),
        }

        let mut ledger = self.ledger.lock().await;
        if let Some(recorded) = ledger.decisions.get(&observation.observation_id) {
            return if recorded.request_digest == request_digest {
                Ok(recorded.decision.clone())
            } else {
                Err(AdmissionError::Replayed)
            };
        }
        if ledger.decisions.len() >= MAX_RECORDED_OBSERVATIONS {
            return Err(AdmissionError::RateLimited);
        }

        let grant = ledger
            .nonces
            .get(&observation.submission_nonce)
            .ok_or(AdmissionError::Replayed)?;
        if grant.expires_at <= now {
            return Err(AdmissionError::Expired);
        }
        if grant.principal != *principal || grant.house_id != observation.challenge.house_id {
            return Err(AdmissionError::MembershipDenied);
        }
        if ledger
            .used_challenges
            .contains(&observation.challenge.challenge_id)
            || ledger
                .used_evidence
                .contains(&observation.corroboration.evidence_id)
        {
            return Err(AdmissionError::Replayed);
        }

        let sequence_key = (principal.clone(), observation.challenge.house_id.clone());
        let current_sequence = ledger.sequences.get(&sequence_key).copied().unwrap_or(0);
        if observation.previous_presence_sequence != current_sequence {
            return Err(AdmissionError::PolicyConflict);
        }
        let next_sequence = current_sequence
            .checked_add(1)
            .ok_or(AdmissionError::PolicyConflict)?;
        let requires_confirmation = observation.direction_requires_confirmation();
        let decision = PresenceDecision {
            schema: PRESENCE_DECISION_SCHEMA.into(),
            decision: if requires_confirmation {
                PresenceDecisionKind::ConfirmationRequired
            } else {
                PresenceDecisionKind::Accepted
            },
            reason: if requires_confirmation {
                PresenceDecisionReason::AmbiguousDirection
            } else {
                PresenceDecisionReason::Accepted
            },
            event_id: Uuid::new_v4(),
            observation_id: observation.observation_id,
            house_id: observation.challenge.house_id.clone(),
            door_id: observation.challenge.door_id.clone(),
            direction: observation.direction,
            presence_sequence: next_sequence,
            policy_version: observation.policy_version.clone(),
            recorded_at: now,
        };

        ledger.nonces.remove(&observation.submission_nonce);
        ledger
            .used_challenges
            .insert(observation.challenge.challenge_id);
        ledger
            .used_evidence
            .insert(observation.corroboration.evidence_id);
        ledger.sequences.insert(sequence_key, next_sequence);
        ledger.decisions.insert(
            observation.observation_id,
            RecordedDecision {
                request_digest,
                decision: decision.clone(),
            },
        );
        Ok(decision)
    }
}

fn observation_digest(observation: &DoorwayObservation) -> Result<[u8; 32], AdmissionError> {
    let encoded = serde_json::to_vec(observation).map_err(|_| AdmissionError::InvalidRequest)?;
    Ok(Sha256::digest(encoded).into())
}

fn valid_identity_component(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() || character == '|')
}

#[cfg(test)]
mod tests {
    use super::*;
    use hhm_interfaces::{
        CorroborationEvidence, CorroborationMethod, DOORWAY_CHALLENGE_SCHEMA,
        DOORWAY_CORROBORATION_SCHEMA, DOORWAY_OBSERVATION_SCHEMA, DoorwayChallenge,
        DoorwayDirection, DoorwayDirectionHint, DoorwaySignalBucket,
        PRESENCE_SUBMISSION_NONCE_REQUEST_SCHEMA, PeerApplication,
    };

    struct FixedVerifier(Verification);

    impl PresenceEvidenceVerifier for FixedVerifier {
        fn verify(
            &self,
            _principal: &PresencePrincipal,
            _observation: &DoorwayObservation,
            _now: DateTime<Utc>,
        ) -> Verification {
            self.0
        }
    }

    struct FixedAuthorizer(ProductAuthorization);

    impl PresenceAuthorizer for FixedAuthorizer {
        fn authorize_nonce(
            &self,
            _principal: &PresencePrincipal,
            _house_id: &str,
        ) -> ProductAuthorization {
            self.0
        }

        fn authorize_observation(
            &self,
            _principal: &PresencePrincipal,
            _observation: &DoorwayObservation,
        ) -> ProductAuthorization {
            self.0
        }
    }

    fn timestamp(value: &str) -> DateTime<Utc> {
        value.parse().expect("valid timestamp")
    }

    fn principal() -> PresencePrincipal {
        PresencePrincipal::from_verified_identity("supabase", "house-prod", "resident-1")
            .expect("valid principal")
    }

    fn nonce_request() -> PresenceSubmissionNonceRequest {
        PresenceSubmissionNonceRequest {
            schema: PRESENCE_SUBMISSION_NONCE_REQUEST_SCHEMA.into(),
            audience: PRESENCE_AUDIENCE.into(),
            house_id: "medellin-house-1".into(),
        }
    }

    fn observation(now: DateTime<Utc>, nonce: String) -> DoorwayObservation {
        DoorwayObservation {
            schema: DOORWAY_OBSERVATION_SCHEMA.into(),
            audience: PRESENCE_AUDIENCE.into(),
            observation_id: Uuid::new_v4(),
            submission_nonce: nonce,
            resident_device_key_id: "device:resident-1".into(),
            app_id: PeerApplication::HhmFlutter,
            direction: DoorwayDirection::Entry,
            signal_bucket: DoorwaySignalBucket::Doorway,
            previous_presence_sequence: 0,
            policy_version: "presence-policy-2026-08".into(),
            challenge: DoorwayChallenge {
                schema: DOORWAY_CHALLENGE_SCHEMA.into(),
                house_id: "medellin-house-1".into(),
                door_id: "front-door".into(),
                beacon_key_id: "door-beacon:front-1".into(),
                key_version: 1,
                challenge_id: Uuid::new_v4(),
                nonce: "b".repeat(43),
                direction_hint: DoorwayDirectionHint::Entry,
                issued_at: now - Duration::seconds(2),
                expires_at: now + Duration::seconds(18),
                signature: "s".repeat(64),
            },
            corroboration: CorroborationEvidence {
                schema: DOORWAY_CORROBORATION_SCHEMA.into(),
                method: CorroborationMethod::DoorController,
                evidence_id: Uuid::new_v4(),
                source_key_id: "door-controller:front-1".into(),
                proof_digest_sha256: "a".repeat(64),
                distance_bucket: DoorwaySignalBucket::Contact,
                observed_at: now - Duration::seconds(1),
                proof: "p".repeat(64),
            },
            observed_at: now,
            device_attestation: "a".repeat(64),
            device_signature: "d".repeat(64),
        }
    }

    fn service(
        verification: Verification,
        authorization: ProductAuthorization,
    ) -> PresenceAdmission<FixedVerifier, FixedAuthorizer> {
        PresenceAdmission::new(
            Arc::new(FixedVerifier(verification)),
            Arc::new(FixedAuthorizer(authorization)),
        )
    }

    #[tokio::test]
    async fn accepts_once_and_returns_the_idempotent_decision() {
        let now = timestamp("2026-08-24T19:00:10Z");
        let principal = principal();
        let service = service(Verification::Verified, ProductAuthorization::Allowed);
        let nonce = service
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        let observation = observation(now, nonce.nonce);

        let first = service
            .submit(&principal, &observation, now)
            .await
            .expect("accepted");
        let duplicate = service
            .submit(&principal, &observation, now)
            .await
            .expect("idempotent duplicate");
        assert_eq!(first, duplicate);
        assert_eq!(first.decision, PresenceDecisionKind::Accepted);
        assert_eq!(first.presence_sequence, 1);
    }

    #[tokio::test]
    async fn one_nonce_cannot_admit_two_observations() {
        let now = timestamp("2026-08-24T19:00:10Z");
        let principal = principal();
        let service = service(Verification::Verified, ProductAuthorization::Allowed);
        let nonce = service
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        let first = observation(now, nonce.nonce.clone());
        service
            .submit(&principal, &first, now)
            .await
            .expect("first accepted");

        let second = observation(now, nonce.nonce);
        assert_eq!(
            service.submit(&principal, &second, now).await,
            Err(AdmissionError::Replayed)
        );
    }

    #[tokio::test]
    async fn uncertain_direction_never_becomes_an_accepted_transition() {
        let now = timestamp("2026-08-24T19:00:10Z");
        let principal = principal();
        let service = service(Verification::Verified, ProductAuthorization::Allowed);
        let nonce = service
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        let mut observation = observation(now, nonce.nonce);
        observation.challenge.direction_hint = DoorwayDirectionHint::Ambiguous;

        let decision = service
            .submit(&principal, &observation, now)
            .await
            .expect("recorded for confirmation");
        assert_eq!(
            decision.decision,
            PresenceDecisionKind::ConfirmationRequired
        );
        assert_eq!(decision.reason, PresenceDecisionReason::AmbiguousDirection);
    }

    #[tokio::test]
    async fn verification_and_product_failures_remain_distinct_and_fail_closed() {
        let now = timestamp("2026-08-24T19:00:10Z");
        let principal = principal();

        let invalid = service(Verification::Invalid, ProductAuthorization::Allowed);
        let nonce = invalid
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        assert_eq!(
            invalid
                .submit(&principal, &observation(now, nonce.nonce), now)
                .await,
            Err(AdmissionError::EvidenceInvalid)
        );

        let unavailable = service(Verification::Unavailable, ProductAuthorization::Allowed);
        let nonce = unavailable
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        assert_eq!(
            unavailable
                .submit(&principal, &observation(now, nonce.nonce), now)
                .await,
            Err(AdmissionError::AuthenticationUnavailable)
        );

        let denied = service(Verification::Verified, ProductAuthorization::Denied);
        assert_eq!(
            denied.issue_nonce(&principal, &nonce_request(), now).await,
            Err(AdmissionError::MembershipDenied)
        );
    }

    #[tokio::test]
    async fn stale_presence_sequence_is_a_policy_conflict() {
        let now = timestamp("2026-08-24T19:00:10Z");
        let principal = principal();
        let service = service(Verification::Verified, ProductAuthorization::Allowed);
        let nonce = service
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        let mut observation = observation(now, nonce.nonce);
        observation.previous_presence_sequence = 9;
        assert_eq!(
            service.submit(&principal, &observation, now).await,
            Err(AdmissionError::PolicyConflict)
        );
    }

    #[tokio::test]
    async fn concurrent_duplicates_converge_on_one_decision() {
        let now = timestamp("2026-08-24T19:00:10Z");
        let principal = principal();
        let service = service(Verification::Verified, ProductAuthorization::Allowed);
        let nonce = service
            .issue_nonce(&principal, &nonce_request(), now)
            .await
            .expect("nonce issued");
        let observation = observation(now, nonce.nonce);

        let left = service.submit(&principal, &observation, now);
        let right = service.submit(&principal, &observation, now);
        let (left, right) = tokio::join!(left, right);
        assert_eq!(left.expect("left decision"), right.expect("right decision"));
    }
}
