use crate::{Diagnostic, Har, Severity};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConversionStats {
    pub datagrams_seen: u64,
    pub tcp_packets_seen: u64,
    pub udp_packets_seen: u64,
    pub connections_seen: u64,
    pub exchanges_emitted: u64,
    pub packets_dropped: u64,
}

#[derive(Debug)]
pub struct ConversionReport {
    pub har: Har,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: ConversionStats,
}

impl ConversionReport {
    pub fn new(har: Har) -> Self {
        Self {
            har,
            diagnostics: Vec::new(),
            stats: ConversionStats::default(),
        }
    }

    pub fn strict_failure(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity != Severity::Info)
    }
}
