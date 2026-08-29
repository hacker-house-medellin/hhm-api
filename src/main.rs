use std::{collections::HashMap, env, sync::Arc};

use anyhow::{Context, bail};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use futures_util::{SinkExt, StreamExt};
use sea_orm::{Database, DatabaseConnection};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info};
use uuid::Uuid;

mod auth;
mod observability;
mod visitor;

use auth::{Authorization, DualAuth};
use observability::Observability;
use visitor::{
    CheckInRequest, CheckOutRequest, IssueQrRequest, VisitorAction, VisitorError, VisitorService,
};

const MAX_MEMBER_NAME_CHARS: usize = 200;
const MAX_ROOM_TYPE_CHARS: usize = 100;
const MAX_WORKSPACE_PLAN_CHARS: usize = 100;
const MAX_NOTES_CHARS: usize = 4_000;
const MAX_STAY_DAYS: i64 = 366;
const RESERVATION_STATUSES: [&str; 5] = [
    "pending",
    "confirmed",
    "checked_in",
    "checked_out",
    "cancelled",
];
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAX_DEMO_RESERVATIONS: usize = 10_000;

#[derive(Clone)]
struct AppState {
    db: Option<DatabaseConnection>,
    records: Arc<RwLock<HashMap<Uuid, Reservation>>>,
    events: broadcast::Sender<String>,
    supabase_url: Option<String>,
    auth: Option<DualAuth>,
    visitors: Option<VisitorService>,
    demo_reservations_enabled: bool,
    observability: Observability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reservation {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub member_name: String,
    pub room_type: String,
    pub check_in: DateTime<Utc>,
    pub check_out: DateTime<Utc>,
    pub workspace_plan: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateReservation {
    pub member_name: String,
    pub room_type: String,
    pub check_in: DateTime<Utc>,
    pub check_out: DateTime<Utc>,
    pub workspace_plan: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Serialize)]
struct ReservationEvent<'a> {
    event: &'static str,
    reservation: &'a Reservation,
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct Health {
    service: &'static str,
    status: &'static str,
    database_configured: bool,
    supabase_configured: bool,
    dual_auth_configured: bool,
    visitor_qr_configured: bool,
    visitor_state_durable: bool,
    demo_reservations_enabled: bool,
    active_visits: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let db = match env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => {
            Some(Database::connect(url).await.context("connect database")?)
        }
        _ => None,
    };
    let (events, _) = broadcast::channel(512);
    let auth = DualAuth::from_environment()?;
    let visitors = VisitorService::from_environment()?;
    if visitors.is_some() && auth.is_none() {
        bail!("visitor QR requires complete Shared Auth and Supabase dual-auth configuration");
    }
    let state = AppState {
        db,
        records: Arc::new(RwLock::new(HashMap::new())),
        events,
        supabase_url: non_empty_env("SUPABASE_URL"),
        auth,
        visitors,
        demo_reservations_enabled: matches!(
            non_empty_env("ALLOW_UNAUTHENTICATED_DEMO_RESERVATIONS").as_deref(),
            Some("true")
        ),
        observability: Observability::new(),
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/reservations", get(list_records).post(create_record))
        .route("/v1/reservations/{id}", get(get_record))
        .route(
            "/v1/visitor-qr/{action}",
            axum::routing::post(issue_visitor_qr),
        )
        .route("/v1/visits/check-in", axum::routing::post(visitor_check_in))
        .route(
            "/v1/visits/check-out",
            axum::routing::post(visitor_check_out),
        )
        .route("/v1/ws", get(ws_upgrade))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(cors_layer()?)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await?;
    info!(address = %listener.local_addr()?, "Hacker House Medellín API listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn cors_layer() -> anyhow::Result<CorsLayer> {
    let origins = parse_cors_origins(&env::var("CORS_ORIGINS").unwrap_or_default())?;
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("x-supabase-token"),
        ]);
    Ok(if origins.is_empty() {
        layer
    } else {
        layer.allow_origin(AllowOrigin::list(origins))
    })
}

fn parse_cors_origins(raw: &str) -> anyhow::Result<Vec<HeaderValue>> {
    let origins = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(parse_cors_origin)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(origins
        .iter()
        .enumerate()
        .filter(|(index, origin)| !origins[..*index].contains(origin))
        .map(|(_, origin)| origin.clone())
        .collect())
}

fn parse_cors_origin(origin: &str) -> anyhow::Result<HeaderValue> {
    if origin == "*" {
        bail!("CORS_ORIGINS must not contain a wildcard");
    }
    let uri = origin
        .parse::<Uri>()
        .with_context(|| format!("invalid CORS origin: {origin}"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
    {
        bail!("CORS origin must be an exact http(s) origin without a path: {origin}");
    }
    origin
        .parse::<HeaderValue>()
        .with_context(|| format!("invalid CORS origin header: {origin}"))
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    let active_visits = match &state.visitors {
        Some(visitors) => visitors.active_visit_count().await,
        None => 0,
    };
    Json(Health {
        service: "hhm-api",
        status: "ok",
        database_configured: state.db.is_some(),
        supabase_configured: state.supabase_url.is_some(),
        dual_auth_configured: state.auth.is_some(),
        visitor_qr_configured: state.visitors.is_some(),
        visitor_state_durable: false,
        demo_reservations_enabled: state.demo_reservations_enabled,
        active_visits,
    })
}

async fn issue_visitor_qr(
    Path(action): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueQrRequest>,
) -> Result<Json<visitor::IssuedQr>, (StatusCode, Json<ApiError>)> {
    let action = action.parse::<VisitorAction>().map_err(visitor_error)?;
    let auth = state.auth.as_ref().ok_or_else(service_not_configured)?;
    match auth.authorize_qr_issuer(&headers).await {
        Authorization::Authorized => state.observability.authorization_event("authorized"),
        Authorization::Anonymous | Authorization::Unauthenticated => {
            state.observability.authorization_event("unauthenticated");
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required",
            ));
        }
        Authorization::Degraded => {
            state.observability.authorization_event("degraded");
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "authentication is temporarily unavailable",
            ));
        }
        Authorization::Forbidden => {
            state.observability.authorization_event("forbidden");
            return Err(api_error(
                StatusCode::FORBIDDEN,
                "forbidden",
                "caller is not authorized to issue visitor QR codes",
            ));
        }
    }

    let visitors = state.visitors.as_ref().ok_or_else(service_not_configured)?;
    let issued = visitors
        .issue(&request.door_id, action, Utc::now())
        .map_err(visitor_error)?;
    state
        .observability
        .visitor_event(action.as_event_name(), "issued", &request.door_id);
    Ok(Json(issued))
}

async fn visitor_check_in(
    State(state): State<AppState>,
    Json(request): Json<CheckInRequest>,
) -> Result<(StatusCode, Json<visitor::CheckInReceipt>), (StatusCode, Json<ApiError>)> {
    let visitors = state.visitors.as_ref().ok_or_else(service_not_configured)?;
    let door_id = request.door_id.clone();
    let receipt = visitors
        .check_in(request, Utc::now())
        .await
        .map_err(visitor_error)?;
    state
        .observability
        .visitor_event("visitor.check_in", "accepted", &door_id);
    Ok((StatusCode::CREATED, Json(receipt)))
}

async fn visitor_check_out(
    State(state): State<AppState>,
    Json(request): Json<CheckOutRequest>,
) -> Result<Json<visitor::CheckOutReceipt>, (StatusCode, Json<ApiError>)> {
    let visitors = state.visitors.as_ref().ok_or_else(service_not_configured)?;
    let door_id = request.door_id.clone();
    let receipt = visitors
        .check_out(request, Utc::now())
        .await
        .map_err(visitor_error)?;
    state
        .observability
        .visitor_event("visitor.check_out", "accepted", &door_id);
    Ok(Json(receipt))
}

async fn list_records(
    State(state): State<AppState>,
) -> Result<Json<Vec<Reservation>>, (StatusCode, Json<ApiError>)> {
    require_demo_reservations(&state)?;
    let mut records = state
        .records
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.created_at);
    Ok(Json(records))
}

async fn get_record(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<Reservation>, (StatusCode, Json<ApiError>)> {
    require_demo_reservations(&state)?;
    state
        .records
        .read()
        .await
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "not_found", "reservation not found"))
}

async fn create_record(
    State(state): State<AppState>,
    Json(input): Json<CreateReservation>,
) -> Result<(StatusCode, Json<Reservation>), (StatusCode, Json<ApiError>)> {
    require_demo_reservations(&state)?;
    let input = normalize_and_validate(input).map_err(|message| {
        api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_reservation",
            message,
        )
    })?;
    let now = Utc::now();
    let record = Reservation {
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        member_name: input.member_name,
        room_type: input.room_type,
        check_in: input.check_in,
        check_out: input.check_out,
        workspace_plan: input.workspace_plan,
        status: input.status,
        notes: input.notes,
    };
    let event = serde_json::to_string(&ReservationEvent {
        event: "reservation.created",
        reservation: &record,
    })
    .map_err(|source| {
        error!(error = %source, "failed to serialize reservation event");
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "event_serialization_failed",
            "reservation could not be created",
        )
    })?;

    let mut records = state.records.write().await;
    if records.len() >= MAX_DEMO_RESERVATIONS {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "reservation_capacity_reached",
            "reservation demo capacity reached",
        ));
    }
    records.insert(record.id, record.clone());
    drop(records);
    let _ = state.events.send(event);
    Ok((StatusCode::CREATED, Json(record)))
}

fn normalize_and_validate(input: CreateReservation) -> Result<CreateReservation, String> {
    let input = normalize(input);
    validate(&input)?;
    Ok(input)
}

fn normalize(input: CreateReservation) -> CreateReservation {
    CreateReservation {
        member_name: input.member_name.trim().to_owned(),
        room_type: input.room_type.trim().to_owned(),
        workspace_plan: input.workspace_plan.trim().to_owned(),
        status: input.status.trim().to_ascii_lowercase(),
        notes: input.notes.trim().to_owned(),
        check_in: input.check_in,
        check_out: input.check_out,
    }
}

fn validate(input: &CreateReservation) -> Result<(), String> {
    validate_required_text("member_name", &input.member_name, MAX_MEMBER_NAME_CHARS)?;
    validate_required_text("room_type", &input.room_type, MAX_ROOM_TYPE_CHARS)?;
    validate_required_text(
        "workspace_plan",
        &input.workspace_plan,
        MAX_WORKSPACE_PLAN_CHARS,
    )?;
    if input.notes.chars().count() > MAX_NOTES_CHARS {
        return Err(format!(
            "notes must be at most {MAX_NOTES_CHARS} characters"
        ));
    }
    if input.check_out <= input.check_in {
        return Err("check_out must be later than check_in".to_owned());
    }
    if input.check_out - input.check_in > Duration::days(MAX_STAY_DAYS) {
        return Err(format!("stay must not exceed {MAX_STAY_DAYS} days"));
    }
    if !RESERVATION_STATUSES.contains(&input.status.as_str()) {
        return Err(format!(
            "status must be one of {}",
            RESERVATION_STATUSES.join(", ")
        ));
    }
    Ok(())
}

fn validate_required_text(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be blank"));
    }
    if value.chars().count() > maximum {
        return Err(format!("{label} must be at most {maximum} characters"));
    }
    Ok(())
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            code,
            message: message.into(),
        }),
    )
}

fn service_not_configured() -> (StatusCode, Json<ApiError>) {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_not_configured",
        "visitor access is not configured",
    )
}

fn require_demo_reservations(state: &AppState) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .demo_reservations_enabled
        .then_some(())
        .ok_or_else(|| {
            api_error(
                StatusCode::FORBIDDEN,
                "reservation_demo_disabled",
                "reservation demo is disabled until authenticated durable storage is configured",
            )
        })
}

fn visitor_error(error: VisitorError) -> (StatusCode, Json<ApiError>) {
    match error {
        VisitorError::InvalidAction
        | VisitorError::InvalidDoor
        | VisitorError::NoticeNotAccepted
        | VisitorError::InvalidVisitorName => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_visitor_request",
            "visitor request is invalid",
        ),
        VisitorError::InvalidQr
        | VisitorError::ExpiredQr
        | VisitorError::VisitNotFound
        | VisitorError::InvalidReceipt => api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_visitor_credential",
            "visitor credential is invalid or expired",
        ),
        VisitorError::CapacityReached => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "visitor_capacity_reached",
            "visitor access is temporarily unavailable",
        ),
        VisitorError::RateLimited => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "visitor_rate_limited",
            "too many visitor check-ins for this QR code",
        ),
        VisitorError::AlreadyCheckedOut => api_error(
            StatusCode::CONFLICT,
            "visitor_already_checked_out",
            "visitor is already checked out",
        ),
    }
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    if let Err(error) = require_demo_reservations(&state) {
        return error.into_response();
    }
    ws.on_upgrade(move |socket| websocket(socket, state))
        .into_response()
}

async fn websocket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = state.events.subscribe();

    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(event) => {
                    if sender.send(Message::Text(event.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    info!(skipped, "WebSocket client lagged behind reservation events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            message = receiver.next() => match message {
                Some(Ok(Message::Ping(payload))) => {
                    if sender.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: &str) -> DateTime<Utc> {
        value.parse().expect("valid test timestamp")
    }

    fn valid_input() -> CreateReservation {
        CreateReservation {
            member_name: "  Ada Lovelace  ".to_owned(),
            room_type: " private ".to_owned(),
            check_in: timestamp("2026-09-01T15:00:00Z"),
            check_out: timestamp("2026-09-14T11:00:00Z"),
            workspace_plan: " dedicated-desk ".to_owned(),
            status: " CONFIRMED ".to_owned(),
            notes: "  Arriving after the community dinner.  ".to_owned(),
        }
    }

    #[test]
    fn normalizes_a_valid_reservation() {
        let normalized = normalize_and_validate(valid_input()).expect("reservation is valid");
        assert_eq!(normalized.member_name, "Ada Lovelace");
        assert_eq!(normalized.room_type, "private");
        assert_eq!(normalized.workspace_plan, "dedicated-desk");
        assert_eq!(normalized.status, "confirmed");
        assert_eq!(normalized.notes, "Arriving after the community dinner.");
    }

    #[test]
    fn rejects_blank_names_and_invalid_dates() {
        let mut blank = valid_input();
        blank.member_name = " \t ".to_owned();
        assert_eq!(
            normalize_and_validate(blank).expect_err("blank name must fail"),
            "member_name must not be blank"
        );

        let mut dates = valid_input();
        dates.check_out = dates.check_in;
        assert_eq!(
            normalize_and_validate(dates).expect_err("invalid dates must fail"),
            "check_out must be later than check_in"
        );
    }

    #[test]
    fn rejects_unknown_statuses_and_unbounded_stays() {
        let mut status = valid_input();
        status.status = "approved-ish".to_owned();
        assert!(
            normalize_and_validate(status)
                .expect_err("unknown status must fail")
                .starts_with("status must be one of")
        );

        let mut stay = valid_input();
        stay.check_out = stay.check_in + Duration::days(MAX_STAY_DAYS + 1);
        assert_eq!(
            normalize_and_validate(stay).expect_err("long stay must fail"),
            format!("stay must not exceed {MAX_STAY_DAYS} days")
        );
    }

    #[test]
    fn reservation_input_is_strict_and_demo_routes_fail_closed() {
        assert!(
            serde_json::from_value::<CreateReservation>(serde_json::json!({
                "member_name": "Ada",
                "room_type": "private",
                "check_in": "2026-09-01T15:00:00Z",
                "check_out": "2026-09-14T11:00:00Z",
                "workspace_plan": "desk",
                "status": "confirmed",
                "notes": "",
                "unexpected": "value"
            }))
            .is_err()
        );

        let (events, _) = broadcast::channel(1);
        let mut state = AppState {
            db: None,
            records: Arc::new(RwLock::new(HashMap::new())),
            events,
            supabase_url: None,
            auth: None,
            visitors: None,
            demo_reservations_enabled: false,
            observability: Observability::new(),
        };
        let denied = require_demo_reservations(&state).expect_err("demo must fail closed");
        assert_eq!(denied.0, StatusCode::FORBIDDEN);
        state.demo_reservations_enabled = true;
        assert!(require_demo_reservations(&state).is_ok());
    }

    #[test]
    fn parses_exact_cors_origins_and_deduplicates_them() {
        let origins = parse_cors_origins(
            "https://app.example.test, https://admin.example.test,https://app.example.test",
        )
        .expect("origins are valid");
        assert_eq!(origins.len(), 2);
        assert_eq!(
            origins[0],
            HeaderValue::from_static("https://app.example.test")
        );
        assert_eq!(
            origins[1],
            HeaderValue::from_static("https://admin.example.test")
        );
    }

    #[test]
    fn rejects_wildcard_and_path_cors_configuration() {
        assert!(parse_cors_origins("*").is_err());
        assert!(parse_cors_origins("https://app.example.test/path").is_err());
        assert!(parse_cors_origins("javascript:alert(1)").is_err());
    }
}
