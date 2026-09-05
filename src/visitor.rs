use std::{
    collections::{HashMap, HashSet},
    env,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::RwLock;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const QR_KEY_ENV: &str = "VISITOR_QR_SIGNING_KEY";
const DOOR_IDS_ENV: &str = "VISITOR_DOOR_IDS";
const NOTICE_VERSION_ENV: &str = "VISITOR_PRIVACY_NOTICE_VERSION";
const QR_SCHEMA: &str = "hhm.visitor-qr.v1";
const QR_AUDIENCE: &str = "hhm-visitor-access";
const TOKEN_PREFIX: &str = "hhm1";
const QR_GRACE_SECONDS: i64 = 15;
const MAX_TOKEN_BYTES: usize = 1_024;
const MAX_PAYLOAD_BYTES: usize = 512;
const MAX_RECEIPT_BYTES: usize = 256;
const MAX_VISITOR_NAME_CHARS: usize = 120;
const MAX_ACTIVE_VISITS: usize = 4_096;
const MAX_REDEMPTIONS_PER_CODE: u16 = 128;
const CLOSED_VISIT_RETENTION_HOURS: i64 = 24;

#[derive(Clone)]
pub struct VisitorService {
    config: Arc<VisitorConfig>,
    state: Arc<RwLock<VisitorState>>,
}

struct VisitorConfig {
    signing_key: Vec<u8>,
    door_ids: HashSet<String>,
    notice_version: String,
}

#[derive(Default)]
struct VisitorState {
    visits: HashMap<Uuid, Visit>,
    redemptions: HashMap<String, (i64, u16)>,
}

struct Visit {
    receipt_tag: Vec<u8>,
    display_name: Option<String>,
    checked_out_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisitorAction {
    CheckIn,
    CheckOut,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueQrRequest {
    pub door_id: String,
}

#[derive(Debug, Serialize)]
pub struct IssuedQr {
    pub action: VisitorAction,
    pub door_id: String,
    pub qr_payload: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckInRequest {
    pub door_id: String,
    pub qr_token: String,
    pub display_name: String,
    pub privacy_notice_version: String,
}

#[derive(Debug, Serialize)]
pub struct CheckInReceipt {
    pub visit_id: Uuid,
    pub checkout_receipt: String,
    pub checked_in_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckOutRequest {
    pub door_id: String,
    pub qr_token: String,
    pub visit_id: Uuid,
    pub checkout_receipt: String,
}

#[derive(Debug, Serialize)]
pub struct CheckOutReceipt {
    pub visit_id: Uuid,
    pub checked_out_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VisitorError {
    InvalidAction,
    InvalidDoor,
    InvalidQr,
    ExpiredQr,
    NoticeNotAccepted,
    InvalidVisitorName,
    CapacityReached,
    RateLimited,
    VisitNotFound,
    InvalidReceipt,
    AlreadyCheckedOut,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QrClaims {
    schema: String,
    audience: String,
    door_id: String,
    action: VisitorAction,
    issued_minute: i64,
}

impl VisitorService {
    pub fn from_environment() -> anyhow::Result<Option<Self>> {
        let key = non_empty_env(QR_KEY_ENV);
        let doors = non_empty_env(DOOR_IDS_ENV);
        let notice = non_empty_env(NOTICE_VERSION_ENV);
        if key.is_none() && doors.is_none() && notice.is_none() {
            return Ok(None);
        }

        let signing_key = URL_SAFE_NO_PAD
            .decode(key.context(format!(
                "{QR_KEY_ENV} is required when visitor QR is enabled"
            ))?)
            .context(format!("{QR_KEY_ENV} must be unpadded base64url"))?;
        if !(32..=64).contains(&signing_key.len()) {
            bail!("{QR_KEY_ENV} must decode to between 32 and 64 bytes");
        }

        let door_ids = parse_door_ids(&doors.context(format!(
            "{DOOR_IDS_ENV} is required when visitor QR is enabled"
        ))?)?;
        let notice_version = notice.context(format!(
            "{NOTICE_VERSION_ENV} is required when visitor QR is enabled"
        ))?;
        if !valid_bounded_text(&notice_version, 64) {
            bail!("{NOTICE_VERSION_ENV} is invalid");
        }

        Ok(Some(Self {
            config: Arc::new(VisitorConfig {
                signing_key,
                door_ids,
                notice_version,
            }),
            state: Arc::new(RwLock::new(VisitorState::default())),
        }))
    }

    pub fn issue(
        &self,
        door_id: &str,
        action: VisitorAction,
        now: DateTime<Utc>,
    ) -> Result<IssuedQr, VisitorError> {
        self.validate_door(door_id)?;
        let minute = now.timestamp().div_euclid(60);
        let token = self.issue_for_minute(door_id, action, minute)?;
        let expiry_seconds = minute
            .checked_add(1)
            .and_then(|value| value.checked_mul(60))
            .and_then(|value| value.checked_add(QR_GRACE_SECONDS))
            .ok_or(VisitorError::InvalidQr)?;
        let expires_at = Utc
            .timestamp_opt(expiry_seconds, 0)
            .single()
            .ok_or(VisitorError::InvalidQr)?;
        Ok(IssuedQr {
            action,
            door_id: door_id.to_owned(),
            qr_payload: format!("hhm-visitor:{token}"),
            expires_at,
        })
    }

    pub async fn check_in(
        &self,
        mut request: CheckInRequest,
        now: DateTime<Utc>,
    ) -> Result<CheckInReceipt, VisitorError> {
        self.verify(
            &request.qr_token,
            &request.door_id,
            VisitorAction::CheckIn,
            now,
        )?;
        if request.privacy_notice_version != self.config.notice_version {
            return Err(VisitorError::NoticeNotAccepted);
        }
        request.display_name = request.display_name.trim().to_owned();
        if !valid_bounded_text(&request.display_name, MAX_VISITOR_NAME_CHARS) {
            return Err(VisitorError::InvalidVisitorName);
        }

        let current_minute = now.timestamp().div_euclid(60);
        let redemption_key = qr_redemption_key(&request.qr_token)?;
        let mut state = self.state.write().await;
        state
            .redemptions
            .retain(|_, (minute, _)| *minute >= current_minute.saturating_sub(2));
        if state
            .redemptions
            .get(&redemption_key)
            .is_some_and(|(_, count)| *count >= MAX_REDEMPTIONS_PER_CODE)
        {
            return Err(VisitorError::RateLimited);
        }

        let closed_before = now - Duration::hours(CLOSED_VISIT_RETENTION_HOURS);
        state.visits.retain(|_, visit| {
            visit
                .checked_out_at
                .is_none_or(|checked_out_at| checked_out_at >= closed_before)
        });
        let active_visits = state
            .visits
            .values()
            .filter(|visit| visit.checked_out_at.is_none())
            .count();
        if active_visits >= MAX_ACTIVE_VISITS {
            return Err(VisitorError::CapacityReached);
        }

        state
            .redemptions
            .entry(redemption_key)
            .and_modify(|entry| entry.1 += 1)
            .or_insert((current_minute, 1));
        let visit_id = Uuid::new_v4();
        let checkout_receipt = format!("{}.{}", Uuid::new_v4(), Uuid::new_v4());
        let receipt_tag = self.receipt_tag(&checkout_receipt)?;
        state.visits.insert(
            visit_id,
            Visit {
                receipt_tag,
                display_name: Some(request.display_name),
                checked_out_at: None,
            },
        );

        Ok(CheckInReceipt {
            visit_id,
            checkout_receipt,
            checked_in_at: now,
        })
    }

    pub async fn check_out(
        &self,
        request: CheckOutRequest,
        now: DateTime<Utc>,
    ) -> Result<CheckOutReceipt, VisitorError> {
        self.verify(
            &request.qr_token,
            &request.door_id,
            VisitorAction::CheckOut,
            now,
        )?;
        if request.checkout_receipt.is_empty() || request.checkout_receipt.len() > MAX_RECEIPT_BYTES
        {
            return Err(VisitorError::InvalidReceipt);
        }
        let mut state = self.state.write().await;
        let visit = state
            .visits
            .get_mut(&request.visit_id)
            .ok_or(VisitorError::VisitNotFound)?;
        if visit.checked_out_at.is_some() {
            return Err(VisitorError::AlreadyCheckedOut);
        }
        self.verify_receipt(&request.checkout_receipt, &visit.receipt_tag)?;
        visit.checked_out_at = Some(now);
        visit.display_name = None;

        Ok(CheckOutReceipt {
            visit_id: request.visit_id,
            checked_out_at: now,
        })
    }

    pub async fn active_visit_count(&self) -> usize {
        self.state
            .read()
            .await
            .visits
            .values()
            .filter(|visit| visit.checked_out_at.is_none())
            .count()
    }

    fn issue_for_minute(
        &self,
        door_id: &str,
        action: VisitorAction,
        minute: i64,
    ) -> Result<String, VisitorError> {
        let claims = QrClaims {
            schema: QR_SCHEMA.to_owned(),
            audience: QR_AUDIENCE.to_owned(),
            door_id: door_id.to_owned(),
            action,
            issued_minute: minute,
        };
        let payload = serde_json::to_vec(&claims).map_err(|_| VisitorError::InvalidQr)?;
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
        let signature = self.sign_token_payload(&encoded_payload)?;
        Ok(format!(
            "{TOKEN_PREFIX}.{encoded_payload}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn verify(
        &self,
        token: &str,
        expected_door: &str,
        expected_action: VisitorAction,
        now: DateTime<Utc>,
    ) -> Result<(), VisitorError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(VisitorError::InvalidQr);
        }
        self.validate_door(expected_door)?;
        let mut segments = token.split('.');
        if segments.next() != Some(TOKEN_PREFIX) {
            return Err(VisitorError::InvalidQr);
        }
        let encoded_payload = segments.next().ok_or(VisitorError::InvalidQr)?;
        let encoded_signature = segments.next().ok_or(VisitorError::InvalidQr)?;
        if segments.next().is_some() || encoded_payload.len() > MAX_PAYLOAD_BYTES * 2 {
            return Err(VisitorError::InvalidQr);
        }

        let signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| VisitorError::InvalidQr)?;
        let mut mac = HmacSha256::new_from_slice(&self.config.signing_key)
            .map_err(|_| VisitorError::InvalidQr)?;
        mac.update(b"hhm.visitor-qr.signature.v1\0");
        mac.update(encoded_payload.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| VisitorError::InvalidQr)?;

        let payload = URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .map_err(|_| VisitorError::InvalidQr)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(VisitorError::InvalidQr);
        }
        let claims: QrClaims =
            serde_json::from_slice(&payload).map_err(|_| VisitorError::InvalidQr)?;
        if claims.schema != QR_SCHEMA
            || claims.audience != QR_AUDIENCE
            || claims.door_id != expected_door
            || claims.action != expected_action
            || !self.config.door_ids.contains(&claims.door_id)
        {
            return Err(VisitorError::InvalidQr);
        }

        let issued_at = claims
            .issued_minute
            .checked_mul(60)
            .ok_or(VisitorError::InvalidQr)?;
        let expires_at = issued_at
            .checked_add(60 + QR_GRACE_SECONDS)
            .ok_or(VisitorError::InvalidQr)?;
        if now.timestamp() < issued_at || now.timestamp() > expires_at {
            return Err(VisitorError::ExpiredQr);
        }
        Ok(())
    }

    fn sign_token_payload(&self, encoded_payload: &str) -> Result<Vec<u8>, VisitorError> {
        let mut mac = HmacSha256::new_from_slice(&self.config.signing_key)
            .map_err(|_| VisitorError::InvalidQr)?;
        mac.update(b"hhm.visitor-qr.signature.v1\0");
        mac.update(encoded_payload.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn receipt_tag(&self, receipt: &str) -> Result<Vec<u8>, VisitorError> {
        let mut mac = HmacSha256::new_from_slice(&self.config.signing_key)
            .map_err(|_| VisitorError::InvalidReceipt)?;
        mac.update(b"hhm.visitor-checkout-receipt.v1\0");
        mac.update(receipt.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify_receipt(&self, receipt: &str, expected_tag: &[u8]) -> Result<(), VisitorError> {
        if receipt.len() > MAX_RECEIPT_BYTES || receipt.chars().any(char::is_control) {
            return Err(VisitorError::InvalidReceipt);
        }
        let mut mac = HmacSha256::new_from_slice(&self.config.signing_key)
            .map_err(|_| VisitorError::InvalidReceipt)?;
        mac.update(b"hhm.visitor-checkout-receipt.v1\0");
        mac.update(receipt.as_bytes());
        mac.verify_slice(expected_tag)
            .map_err(|_| VisitorError::InvalidReceipt)
    }

    fn validate_door(&self, door_id: &str) -> Result<(), VisitorError> {
        self.config
            .door_ids
            .contains(door_id)
            .then_some(())
            .ok_or(VisitorError::InvalidDoor)
    }
}

impl VisitorAction {
    pub const fn as_event_name(self) -> &'static str {
        match self {
            Self::CheckIn => "visitor.check_in",
            Self::CheckOut => "visitor.check_out",
        }
    }
}

impl FromStr for VisitorAction {
    type Err = VisitorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "check-in" => Ok(Self::CheckIn),
            "check-out" => Ok(Self::CheckOut),
            _ => Err(VisitorError::InvalidAction),
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_door_ids(raw: &str) -> anyhow::Result<HashSet<String>> {
    let mut doors = HashSet::new();
    for door in raw
        .split(',')
        .map(str::trim)
        .filter(|door| !door.is_empty())
    {
        let valid = door.len() <= 64
            && door.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            });
        if !valid {
            bail!("{DOOR_IDS_ENV} contains an invalid door identifier");
        }
        doors.insert(door.to_owned());
    }
    if doors.is_empty() {
        bail!("{DOOR_IDS_ENV} must contain at least one door identifier");
    }
    Ok(doors)
}

fn valid_bounded_text(value: &str, maximum_chars: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= maximum_chars
        && !value.chars().any(char::is_control)
}

fn qr_redemption_key(token: &str) -> Result<String, VisitorError> {
    token
        .rsplit_once('.')
        .map(|(_, signature)| signature.to_owned())
        .filter(|signature| !signature.is_empty() && signature.len() <= 64)
        .ok_or(VisitorError::InvalidQr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: &str) -> DateTime<Utc> {
        value.parse().expect("valid timestamp")
    }

    fn service() -> VisitorService {
        VisitorService {
            config: Arc::new(VisitorConfig {
                signing_key: vec![7; 32],
                door_ids: HashSet::from(["front-door".to_owned(), "garden-door".to_owned()]),
                notice_version: "privacy-2026-08".to_owned(),
            }),
            state: Arc::new(RwLock::new(VisitorState::default())),
        }
    }

    #[test]
    fn qr_payload_changes_each_minute_and_has_short_grace() {
        let service = service();
        let first = service
            .issue(
                "front-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:00:10Z"),
            )
            .unwrap();
        let second = service
            .issue(
                "front-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:01:00Z"),
            )
            .unwrap();
        assert_ne!(first.qr_payload, second.qr_payload);

        let token = first.qr_payload.trim_start_matches("hhm-visitor:");
        assert!(
            service
                .verify(
                    token,
                    "front-door",
                    VisitorAction::CheckIn,
                    timestamp("2026-08-24T12:01:15Z")
                )
                .is_ok()
        );
        assert_eq!(
            service.verify(
                token,
                "front-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:01:16Z")
            ),
            Err(VisitorError::ExpiredQr)
        );
    }

    #[test]
    fn qr_claim_uses_the_purpose_specific_visitor_audience() {
        let issued = service()
            .issue(
                "front-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:00:10Z"),
            )
            .unwrap();
        let token = issued.qr_payload.trim_start_matches("hhm-visitor:");
        let encoded_claims = token.split('.').nth(1).unwrap();
        let claims: QrClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_claims).unwrap()).unwrap();
        assert_eq!(claims.audience, "hhm-visitor-access");
    }

    #[test]
    fn qr_is_bound_to_action_door_and_signature() {
        let service = service();
        let issued = service
            .issue(
                "front-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:00:10Z"),
            )
            .unwrap();
        let token = issued.qr_payload.trim_start_matches("hhm-visitor:");
        assert_eq!(
            service.verify(
                token,
                "garden-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:00:20Z")
            ),
            Err(VisitorError::InvalidQr)
        );
        assert_eq!(
            service.verify(
                token,
                "front-door",
                VisitorAction::CheckOut,
                timestamp("2026-08-24T12:00:20Z")
            ),
            Err(VisitorError::InvalidQr)
        );
        let mut tampered = token.to_owned();
        tampered.push('x');
        assert_eq!(
            service.verify(
                &tampered,
                "front-door",
                VisitorAction::CheckIn,
                timestamp("2026-08-24T12:00:20Z")
            ),
            Err(VisitorError::InvalidQr)
        );
    }

    #[test]
    fn visitor_requests_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<IssueQrRequest>(serde_json::json!({
                "door_id": "front-door",
                "unexpected": "value"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CheckInRequest>(serde_json::json!({
                "door_id": "front-door",
                "qr_token": "token",
                "display_name": "Ada",
                "privacy_notice_version": "privacy-2026-08",
                "unexpected": "value"
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn check_in_and_out_require_notice_and_private_receipt() {
        let service = service();
        let check_in_time = timestamp("2026-08-24T12:00:10Z");
        let check_in_qr = service
            .issue("front-door", VisitorAction::CheckIn, check_in_time)
            .unwrap();
        let token = check_in_qr
            .qr_payload
            .trim_start_matches("hhm-visitor:")
            .to_owned();

        let wrong_notice = service
            .check_in(
                CheckInRequest {
                    door_id: "front-door".to_owned(),
                    qr_token: token.clone(),
                    display_name: "Ada".to_owned(),
                    privacy_notice_version: "old".to_owned(),
                },
                check_in_time,
            )
            .await;
        assert!(matches!(wrong_notice, Err(VisitorError::NoticeNotAccepted)));

        let receipt = service
            .check_in(
                CheckInRequest {
                    door_id: "front-door".to_owned(),
                    qr_token: token,
                    display_name: "  Ada Lovelace  ".to_owned(),
                    privacy_notice_version: "privacy-2026-08".to_owned(),
                },
                check_in_time,
            )
            .await
            .unwrap();
        assert_eq!(service.active_visit_count().await, 1);

        let check_out_time = timestamp("2026-08-24T13:00:05Z");
        let check_out_qr = service
            .issue("garden-door", VisitorAction::CheckOut, check_out_time)
            .unwrap();
        let check_out_token = check_out_qr
            .qr_payload
            .trim_start_matches("hhm-visitor:")
            .to_owned();
        let rejected = service
            .check_out(
                CheckOutRequest {
                    door_id: "garden-door".to_owned(),
                    qr_token: check_out_token.clone(),
                    visit_id: receipt.visit_id,
                    checkout_receipt: "wrong".to_owned(),
                },
                check_out_time,
            )
            .await;
        assert!(matches!(rejected, Err(VisitorError::InvalidReceipt)));

        service
            .check_out(
                CheckOutRequest {
                    door_id: "garden-door".to_owned(),
                    qr_token: check_out_token,
                    visit_id: receipt.visit_id,
                    checkout_receipt: receipt.checkout_receipt,
                },
                check_out_time,
            )
            .await
            .unwrap();
        assert_eq!(service.active_visit_count().await, 0);
    }
}
