#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticScope {
    Capture,
    Datagram { index: u64 },
    Connection { connection: u64 },
    Packet { connection: u64, packet: u64 },
    Stream { connection: u64, stream: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCode {
    UnsupportedLinkType,
    MalformedDatagram,
    MissingSecret,
    AuthenticationFailed,
    ResourceLimit,
    IncompleteStream,
    UnsupportedProtocol,
    TruncatedCapture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: DiagnosticCode,
    pub scope: DiagnosticScope,
    pub message: String,
}

impl Diagnostic {
    pub fn info(code: DiagnosticCode, scope: DiagnosticScope, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, scope, message)
    }

    pub fn warning(
        code: DiagnosticCode,
        scope: DiagnosticScope,
        message: impl Into<String>,
    ) -> Self {
        Self::new(Severity::Warning, code, scope, message)
    }

    pub fn error(code: DiagnosticCode, scope: DiagnosticScope, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, scope, message)
    }

    fn new(
        severity: Severity,
        code: DiagnosticCode,
        scope: DiagnosticScope,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code,
            scope,
            message: message.into(),
        }
    }
}
