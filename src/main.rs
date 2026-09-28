use clap::{error::ErrorKind, Parser};
use pcap2har::{
    convert_capture, ConversionOptions, ConversionReport, DecodeLimits, DiagnosticCode,
    DiagnosticScope, Har, Severity,
};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser)]
#[command(name = "pcap2har")]
#[command(about = "Convert PCAP files to HAR format")]
#[command(version)]
struct Cli {
    /// Input PCAP or PCAPNG file
    #[arg(value_name = "PCAP_FILE")]
    input: PathBuf,

    /// Output HAR file (stdout if not specified)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// NSS key log sidecar file
    #[arg(long, value_name = "FILE")]
    keylog: Option<PathBuf>,

    /// Return exit code 2 when partial conversion diagnostics are present
    #[arg(long)]
    strict: bool,

    /// Maximum buffered payload budget per conversion stage in MiB
    #[arg(long, value_name = "MIB", default_value = "256")]
    max_memory_mib: String,

    /// Maximum size of a single decoded HTTP body in MiB; larger bodies are truncated
    #[arg(long, value_name = "MIB", default_value = "16")]
    max_body_mib: String,

    /// Emit each body as _sha1/_sha256 hashes and a base64 _prefix of its first BYTES bytes
    /// instead of its full text, keeping the HAR small
    #[arg(long, value_name = "BYTES")]
    body_summary: Option<usize>,
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = error.print();
            if informational {
                return;
            }
            process::exit(1);
        }
    };
    let exit_code = match run(cli) {
        Ok(exit_code) => exit_code,
        Err(message) => {
            eprintln!("{message}");
            1
        }
    };
    if exit_code != 0 {
        process::exit(exit_code);
    }
}

fn run(cli: Cli) -> Result<i32, String> {
    let max_memory_bytes = parse_mib("--max-memory-mib", &cli.max_memory_mib)?;
    let max_body_bytes = parse_mib("--max-body-mib", &cli.max_body_mib)?;
    let defaults = DecodeLimits::default();
    // A body can only be as large as the stream and connection that carry it, so
    // those caps grow with the body cap (headroom for headers and the other direction).
    let max_stream_bytes = defaults
        .max_stream_bytes
        .max(max_body_bytes.saturating_add(defaults.max_header_section_bytes));
    // Sized for 512-byte segments so the TCP segment count never binds before the byte cap.
    let max_segments_per_stream = defaults
        .max_segments_per_stream
        .max(max_stream_bytes.min(max_memory_bytes) / 512);
    let max_connection_bytes = defaults
        .max_connection_bytes
        .max(max_stream_bytes.saturating_mul(2));
    let limits = DecodeLimits {
        capture_buffer_bytes: defaults.capture_buffer_bytes.min(max_memory_bytes),
        max_stream_bytes: max_stream_bytes.min(max_memory_bytes),
        max_segments_per_stream,
        max_connection_bytes: max_connection_bytes.min(max_memory_bytes),
        max_total_buffered_bytes: max_memory_bytes,
        max_frame_bytes: defaults.max_frame_bytes.min(max_memory_bytes),
        max_header_section_bytes: defaults.max_header_section_bytes.min(max_memory_bytes),
        max_body_bytes: max_body_bytes.min(max_memory_bytes),
        max_qpack_table_bytes: defaults.max_qpack_table_bytes.min(max_memory_bytes),
        ..defaults
    };
    let options = ConversionOptions {
        keylog: cli.keylog,
        strict: cli.strict,
        limits,
        body_summary_bytes: cli.body_summary,
    };

    let report = convert_capture(&cli.input, options)
        .map_err(|error| format!("conversion failed: {error}"))?;
    write_har(&report.har, cli.output.as_deref())?;
    write_report(&report);

    Ok(if cli.strict && report.strict_failure() {
        2
    } else {
        0
    })
}

fn parse_mib(flag: &str, value: &str) -> Result<usize, String> {
    const BYTES_PER_MIB: u128 = 1024 * 1024;
    let mib = value
        .parse::<u128>()
        .map_err(|_| format!("invalid {flag}: expected a positive integer"))?;
    if mib == 0 {
        return Err(format!("invalid {flag}: value must be greater than zero"));
    }
    mib.checked_mul(BYTES_PER_MIB)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| format!("invalid {flag}: value is too large"))
}

fn write_har(har: &Har, output: Option<&Path>) -> Result<(), String> {
    match output {
        Some(path) => {
            let mut file =
                File::create(path).map_err(|_| "unable to create output file".to_string())?;
            serde_json::to_writer_pretty(&mut file, har)
                .map_err(|_| "unable to serialize HAR".to_string())?;
            file.write_all(b"\n")
                .map_err(|_| "unable to write output file".to_string())
        }
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            serde_json::to_writer_pretty(&mut handle, har)
                .map_err(|_| "unable to serialize HAR".to_string())?;
            handle
                .write_all(b"\n")
                .map_err(|_| "unable to write HAR to stdout".to_string())
        }
    }
}

fn write_report(report: &ConversionReport) {
    for diagnostic in &report.diagnostics {
        eprintln!(
            "diagnostic severity={} code={} scope={} message={}",
            severity_name(diagnostic.severity),
            diagnostic_code_name(diagnostic.code),
            diagnostic_scope_name(&diagnostic.scope),
            diagnostic.message
        );
    }
    eprintln!(
        "stats datagrams={} tcp={} udp={} connections={} exchanges={} dropped={}",
        report.stats.datagrams_seen,
        report.stats.tcp_packets_seen,
        report.stats.udp_packets_seen,
        report.stats.connections_seen,
        report.stats.exchanges_emitted,
        report.stats.packets_dropped
    );
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn diagnostic_code_name(code: DiagnosticCode) -> &'static str {
    match code {
        DiagnosticCode::UnsupportedLinkType => "unsupported_link_type",
        DiagnosticCode::MalformedDatagram => "malformed_datagram",
        DiagnosticCode::MissingSecret => "missing_secret",
        DiagnosticCode::AuthenticationFailed => "authentication_failed",
        DiagnosticCode::ResourceLimit => "resource_limit",
        DiagnosticCode::IncompleteStream => "incomplete_stream",
        DiagnosticCode::UnsupportedProtocol => "unsupported_protocol",
        DiagnosticCode::TruncatedCapture => "truncated_capture",
    }
}

fn diagnostic_scope_name(scope: &DiagnosticScope) -> String {
    match scope {
        DiagnosticScope::Capture => "capture".to_string(),
        DiagnosticScope::Datagram { index } => format!("datagram:{index}"),
        DiagnosticScope::Connection { connection } => format!("connection:{connection}"),
        DiagnosticScope::Packet { connection, packet } => {
            format!("connection:{connection}/packet:{packet}")
        }
        DiagnosticScope::Stream { connection, stream } => {
            format!("connection:{connection}/stream:{stream}")
        }
    }
}
