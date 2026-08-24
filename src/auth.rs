use std::{collections::HashSet, env, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use axum::http::{HeaderMap, Uri};
use shared_auth_lib::{AuthOutcome, AuthorityConfig, Guard, GuardConfig};

const SHARED_AUTH_BASE_URL: &str = "SHARED_AUTH_BASE_URL";
const SHARED_AUTH_ISSUER: &str = "SHARED_AUTH_ISSUER";
const SHARED_AUTH_AUDIENCE: &str = "SHARED_AUTH_AUDIENCE";
const AUTH_INTROSPECT_SECRET: &str = "AUTH_INTROSPECT_SECRET";
const SUPABASE_URL: &str = "SUPABASE_URL";
const SUPABASE_PROJECT_REF: &str = "SUPABASE_PROJECT_REF";
const SUPABASE_ANON_KEY: &str = "SUPABASE_ANON_KEY";
const QR_ISSUER_IDENTITIES: &str = "HHM_QR_ISSUER_IDENTITIES";

const REQUIRED_CONFIGURATION: [&str; 8] = [
    SHARED_AUTH_BASE_URL,
    SHARED_AUTH_ISSUER,
    SHARED_AUTH_AUDIENCE,
    AUTH_INTROSPECT_SECRET,
    SUPABASE_URL,
    SUPABASE_PROJECT_REF,
    SUPABASE_ANON_KEY,
    QR_ISSUER_IDENTITIES,
];

#[derive(Clone)]
pub struct DualAuth {
    guard: Arc<Guard>,
    qr_issuers: HashSet<IdentityKey>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct IdentityKey {
    provider: String,
    tenant: String,
    subject: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authorization {
    Authorized,
    Anonymous,
    Unauthenticated,
    Degraded,
    Forbidden,
}

impl DualAuth {
    pub fn from_environment() -> anyhow::Result<Option<Self>> {
        let configured = REQUIRED_CONFIGURATION
            .iter()
            .filter_map(|name| non_empty_env(name).map(|value| (*name, value)))
            .collect::<std::collections::HashMap<_, _>>();
        if configured.is_empty() {
            return Ok(None);
        }

        let required = |name: &'static str| {
            configured
                .get(name)
                .cloned()
                .with_context(|| format!("{name} is required when dual authentication is enabled"))
        };
        let shared_auth_base = required(SHARED_AUTH_BASE_URL)?;
        let issuer = required(SHARED_AUTH_ISSUER)?;
        let audience = required(SHARED_AUTH_AUDIENCE)?;
        let introspect_secret = required(AUTH_INTROSPECT_SECRET)?;
        let supabase_url = required(SUPABASE_URL)?;
        let supabase_project = required(SUPABASE_PROJECT_REF)?;
        let supabase_api_key = required(SUPABASE_ANON_KEY)?;
        let qr_issuers = parse_identity_allowlist(&required(QR_ISSUER_IDENTITIES)?)?;

        validate_remote_url(SHARED_AUTH_BASE_URL, &shared_auth_base)?;
        validate_remote_url(SHARED_AUTH_ISSUER, &issuer)?;
        validate_remote_url(SUPABASE_URL, &supabase_url)?;
        validate_identifier(SHARED_AUTH_AUDIENCE, &audience, 255)?;
        validate_identifier(SUPABASE_PROJECT_REF, &supabase_project, 255)?;

        let guard = Guard::new(GuardConfig {
            authority: AuthorityConfig {
                shared_auth_base,
                issuer,
                audience,
                supabase_url: Some(supabase_url),
                supabase_api_key: Some(supabase_api_key),
                introspect_secret: Some(introspect_secret),
                arm_timeout: Duration::from_millis(1_200),
            },
            supabase_project: Some(supabase_project),
            login_url: "/auth/sign-in".to_owned(),
            race_deadline: Duration::from_millis(1_500),
            ..GuardConfig::default()
        });

        Ok(Some(Self {
            guard: Arc::new(guard),
            qr_issuers,
        }))
    }

    pub async fn authorize_qr_issuer(&self, headers: &HeaderMap) -> Authorization {
        match self.guard.check(headers).await {
            AuthOutcome::Authenticated { identity, .. } => {
                let authorized = IdentityKey::from_verified_identity(
                    &identity.provider,
                    &identity.provider_tenant,
                    &identity.provider_subject,
                )
                .is_some_and(|key| self.qr_issuers.contains(&key));
                if authorized {
                    Authorization::Authorized
                } else {
                    Authorization::Forbidden
                }
            }
            AuthOutcome::Anonymous => Authorization::Anonymous,
            AuthOutcome::Unauthenticated => Authorization::Unauthenticated,
            AuthOutcome::Degraded { .. } => Authorization::Degraded,
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_identity_allowlist(raw: &str) -> anyhow::Result<HashSet<IdentityKey>> {
    let mut identities = HashSet::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let parts = entry.split('|').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 3 {
            bail!(
                "{QR_ISSUER_IDENTITIES} entries must use provider|tenant|subject without email addresses"
            );
        }
        let identity = IdentityKey::from_verified_identity(parts[0], parts[1], parts[2])
            .with_context(|| {
                format!("{QR_ISSUER_IDENTITIES} contains an invalid identity tuple")
            })?;
        identities.insert(identity);
    }
    if identities.is_empty() {
        bail!("{QR_ISSUER_IDENTITIES} must contain at least one exact identity tuple");
    }
    Ok(identities)
}

impl IdentityKey {
    fn from_verified_identity(provider: &str, tenant: &str, subject: &str) -> Option<Self> {
        valid_component(provider, 64)
            .then_some(())
            .filter(|_| valid_component(tenant, 255))
            .filter(|_| valid_component(subject, 512))
            .map(|_| Self {
                provider: provider.to_owned(),
                tenant: tenant.to_owned(),
                subject: subject.to_owned(),
            })
    }
}

fn valid_component(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() || character == '|')
}

fn validate_identifier(name: &str, value: &str, maximum: usize) -> anyhow::Result<()> {
    if !valid_component(value, maximum) {
        bail!("{name} is invalid");
    }
    Ok(())
}

fn validate_remote_url(name: &str, value: &str) -> anyhow::Result<()> {
    let uri = value
        .parse::<Uri>()
        .with_context(|| format!("{name} must be an absolute URL"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    let host = uri.host().unwrap_or_default();
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
    if uri.authority().is_none() || (scheme != "https" && !(scheme == "http" && loopback)) {
        bail!("{name} must use HTTPS, except for explicit loopback development");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_provider_identity_tuples() {
        let identities =
            parse_identity_allowlist("supabase|house-prod|subject-1, local|default|resident-kiosk")
                .expect("valid allowlist");
        assert!(identities.contains(&IdentityKey {
            provider: "supabase".to_owned(),
            tenant: "house-prod".to_owned(),
            subject: "subject-1".to_owned(),
        }));
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn rejects_email_or_partial_identity_shortcuts() {
        assert!(parse_identity_allowlist("person@example.com").is_err());
        assert!(parse_identity_allowlist("supabase|tenant").is_err());
        assert!(parse_identity_allowlist("supabase|tenant|bad|subject").is_err());
    }

    #[test]
    fn rejects_plaintext_remote_authorities() {
        assert!(validate_remote_url("AUTHORITY", "http://auth.example.test").is_err());
        assert!(validate_remote_url("AUTHORITY", "http://127.0.0.1:8080").is_ok());
        assert!(validate_remote_url("AUTHORITY", "https://auth.example.test").is_ok());
    }
}
