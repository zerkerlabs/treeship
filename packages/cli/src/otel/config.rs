/// Configuration for the OpenTelemetry exporter.
///
/// All values come from environment variables:
///   TREESHIP_OTEL_ENDPOINT  - OTLP/HTTP endpoint (required)
///   TREESHIP_OTEL_AUTH      - Authorization header value (optional)
///   TREESHIP_OTEL_SERVICE   - service.name resource attribute (default: "treeship")
///   TREESHIP_OTEL_ENABLED   - set to "0" or "false" to disable (default: enabled)
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// OTLP/HTTP endpoint, e.g. "http://localhost:4318"
    pub endpoint: String,

    /// Optional Authorization header (e.g. "Bearer sk-..." or "Basic ...")
    pub auth_header: Option<String>,

    /// service.name shown in the observability platform
    pub service_name: String,

    /// Master switch -- can disable without removing config
    pub enabled: bool,
}

impl OtelConfig {
    /// Reads config from environment variables.
    /// Returns None if TREESHIP_OTEL_ENDPOINT is not set.
    pub fn from_env() -> Option<Self> {
        let endpoint = std::env::var("TREESHIP_OTEL_ENDPOINT").ok()?;
        Some(Self {
            endpoint,
            auth_header: std::env::var("TREESHIP_OTEL_AUTH").ok(),
            service_name: std::env::var("TREESHIP_OTEL_SERVICE")
                .unwrap_or_else(|_| "treeship".into()),
            enabled: std::env::var("TREESHIP_OTEL_ENABLED")
                .map(|v| v != "0" && v != "false")
                .unwrap_or(true),
        })
    }
}
