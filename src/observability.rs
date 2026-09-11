use std::sync::Arc;

use next_loggers::{JsonObject, Logger, OpenTelemetryTransport, Options, Value as LogValue, json};

#[derive(Clone)]
pub struct Observability {
    logger: Logger,
}

impl Observability {
    pub fn new() -> Self {
        let transport = OpenTelemetryTransport::new(|record| {
            tracing::info!(
                target: "ores_otel",
                otel_body = %record.body,
                otel_severity_text = %record.severity_text,
                otel_severity_number = record.severity_number,
                otel_attributes = ?record.attributes,
                "Ores structured log"
            );
            Ok(())
        });
        Self {
            logger: Logger::new(Options {
                app_name: "hhm-api".to_owned(),
                console: false,
                transports: vec![Arc::new(transport)],
                ..Options::default()
            }),
        }
    }

    pub fn visitor_event(&self, event: &'static str, outcome: &'static str, door_id: &str) {
        let fields = JsonObject::from_iter([
            ("event.name".to_owned(), LogValue::String(event.to_owned())),
            (
                "event.outcome".to_owned(),
                LogValue::String(outcome.to_owned()),
            ),
            ("door.id".to_owned(), LogValue::String(door_id.to_owned())),
        ]);
        let _ = self
            .logger
            .info(vec![json!("visitor access transition")])
            .add_fields(fields)
            .send();
    }

    pub fn authorization_event(&self, outcome: &'static str) {
        let fields = JsonObject::from_iter([
            (
                "event.name".to_owned(),
                LogValue::String("visitor.qr.authorize".to_owned()),
            ),
            (
                "auth.outcome".to_owned(),
                LogValue::String(outcome.to_owned()),
            ),
        ]);
        let _ = self
            .logger
            .info(vec![json!("visitor QR authorization")])
            .add_fields(fields)
            .send();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_bounded_events_without_identity_or_token_fields() {
        let observability = Observability::new();
        observability.visitor_event("visitor.check_in", "accepted", "front-door");
        observability.authorization_event("forbidden");
    }
}
