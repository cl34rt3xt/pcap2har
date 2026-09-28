use chrono::{DateTime, Utc};
use flate2::read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use httparse::{Request, Response, Status, EMPTY_HEADER};
use std::borrow::Cow;
use std::io::Read;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Incomplete data")]
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub header_size: usize,
}

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub header_size: usize,
    /// Body length as transferred: after de-chunking, before `Content-Encoding` is undone.
    pub encoded_body_size: usize,
    /// `body` is not the whole body: a decode limit was hit, or the capture holds less
    /// than `Content-Length` or the chunked framing says was sent.
    pub body_truncated: bool,
}

pub fn parse_request(data: &[u8]) -> Result<Option<ParsedRequest>, HttpError> {
    parse_request_bounded(data, usize::MAX).map(|(request, _)| request)
}

/// Parses one request and reports whether its body exceeded `max_body_bytes`.
pub fn parse_request_bounded(
    data: &[u8],
    max_body_bytes: usize,
) -> Result<(Option<ParsedRequest>, bool), HttpError> {
    let mut headers = [EMPTY_HEADER; 64];
    let mut req = Request::new(&mut headers);

    match req.parse(data) {
        Ok(Status::Complete(header_len)) => {
            let method = req.method.unwrap_or("").to_string();
            let path = req.path.unwrap_or("").to_string();
            let version = format!("HTTP/1.{}", req.version.unwrap_or(1));

            let headers: Vec<(String, String)> = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();

            let extracted = extract_body_bounded(&data[header_len..], &headers, max_body_bytes);

            Ok((
                Some(ParsedRequest {
                    method,
                    path,
                    version,
                    headers,
                    body: extracted.body,
                    header_size: header_len,
                }),
                extracted.limit_exceeded,
            ))
        }
        Ok(Status::Partial) => Err(HttpError::Incomplete),
        Err(e) => Err(HttpError::Parse(e.to_string())),
    }
}

/// Parse multiple HTTP requests from a single data stream (HTTP/1.1 Keep-Alive)
pub fn parse_all_requests(data: &[u8]) -> Vec<ParsedRequest> {
    parse_all_requests_bounded(data, usize::MAX, usize::MAX).0
}

/// Parses keep-alive requests with independent per-body and aggregate body limits.
pub fn parse_all_requests_bounded(
    data: &[u8],
    max_body_bytes: usize,
    max_total_body_bytes: usize,
) -> (Vec<ParsedRequest>, bool) {
    let mut requests = Vec::new();
    let mut offset = 0;
    let mut body_limit_exceeded = false;
    let mut remaining_body_bytes = max_total_body_bytes;

    while offset < data.len() {
        let remaining = &data[offset..];

        let mut headers = [EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        match req.parse(remaining) {
            Ok(Status::Complete(header_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let version = format!("HTTP/1.{}", req.version.unwrap_or(1));

                let headers: Vec<(String, String)> = req
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                let extracted = extract_body_bounded(
                    &remaining[header_len..],
                    &headers,
                    max_body_bytes.min(remaining_body_bytes),
                );
                remaining_body_bytes = remaining_body_bytes.saturating_sub(extracted.body.len());
                body_limit_exceeded |= extracted.limit_exceeded;

                requests.push(ParsedRequest {
                    method,
                    path,
                    version,
                    headers,
                    body: extracted.body,
                    header_size: header_len,
                });

                offset += header_len + extracted.consumed;
            }
            _ => break,
        }
    }

    (requests, body_limit_exceeded)
}

pub fn parse_response(data: &[u8]) -> Result<Option<ParsedResponse>, HttpError> {
    parse_response_bounded(data, usize::MAX).map(|(response, _)| response)
}

/// Parses one response and reports whether its decoded body exceeded the limit.
pub fn parse_response_bounded(
    data: &[u8],
    max_body_bytes: usize,
) -> Result<(Option<ParsedResponse>, bool), HttpError> {
    let mut headers = [EMPTY_HEADER; 64];
    let mut resp = Response::new(&mut headers);

    match resp.parse(data) {
        Ok(Status::Complete(header_len)) => {
            let status = resp.code.unwrap_or(0);
            let reason = resp.reason.unwrap_or("").to_string();
            let version = format!("HTTP/1.{}", resp.version.unwrap_or(1));

            let headers: Vec<(String, String)> = resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();

            let extracted = extract_body_bounded(&data[header_len..], &headers, max_body_bytes);

            Ok((
                Some(ParsedResponse {
                    status,
                    reason,
                    version,
                    headers,
                    encoded_body_size: extracted.encoded_size,
                    body_truncated: extracted.truncated(),
                    body: extracted.body,
                    header_size: header_len,
                }),
                extracted.limit_exceeded,
            ))
        }
        Ok(Status::Partial) => Err(HttpError::Incomplete),
        Err(e) => Err(HttpError::Parse(e.to_string())),
    }
}

/// Parse multiple HTTP responses from a single data stream (HTTP/1.1 Keep-Alive)
pub fn parse_all_responses(data: &[u8]) -> Vec<ParsedResponse> {
    parse_all_responses_bounded(data, usize::MAX, usize::MAX).0
}

/// Parses keep-alive responses with independent per-body and aggregate body limits.
pub fn parse_all_responses_bounded(
    data: &[u8],
    max_body_bytes: usize,
    max_total_body_bytes: usize,
) -> (Vec<ParsedResponse>, bool) {
    let mut responses = Vec::new();
    let mut offset = 0;
    let mut body_limit_exceeded = false;
    let mut remaining_body_bytes = max_total_body_bytes;

    while offset < data.len() {
        let remaining = &data[offset..];

        let mut headers = [EMPTY_HEADER; 64];
        let mut resp = Response::new(&mut headers);

        match resp.parse(remaining) {
            Ok(Status::Complete(header_len)) => {
                let status = resp.code.unwrap_or(0);
                let reason = resp.reason.unwrap_or("").to_string();
                let version = format!("HTTP/1.{}", resp.version.unwrap_or(1));

                let headers: Vec<(String, String)> = resp
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                let extracted = extract_body_bounded(
                    &remaining[header_len..],
                    &headers,
                    max_body_bytes.min(remaining_body_bytes),
                );
                remaining_body_bytes = remaining_body_bytes.saturating_sub(extracted.body.len());
                body_limit_exceeded |= extracted.limit_exceeded;

                responses.push(ParsedResponse {
                    status,
                    reason,
                    version,
                    headers,
                    encoded_body_size: extracted.encoded_size,
                    body_truncated: extracted.truncated(),
                    body: extracted.body,
                    header_size: header_len,
                });

                offset += header_len + extracted.consumed;
            }
            _ => break,
        }
    }

    (responses, body_limit_exceeded)
}

#[cfg(test)]
fn extract_body_with_length(data: &[u8], headers: &[(String, String)]) -> (Vec<u8>, usize) {
    let extracted = extract_body_bounded(data, headers, usize::MAX);
    (extracted.body, extracted.consumed)
}

struct ExtractedBody {
    /// Decoded body, capped at the body limit.
    body: Vec<u8>,
    /// Stream bytes the message body occupies, including chunk framing.
    consumed: usize,
    /// Body length as transferred: after de-chunking, before content decoding.
    encoded_size: usize,
    limit_exceeded: bool,
    /// The capture ends before the body does.
    incomplete: bool,
}

impl ExtractedBody {
    fn truncated(&self) -> bool {
        self.limit_exceeded || self.incomplete
    }
}

fn extract_body_bounded(
    data: &[u8],
    headers: &[(String, String)],
    max_body_bytes: usize,
) -> ExtractedBody {
    let content_length = headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());

    let is_chunked = headers.iter().any(|(k, v)| {
        k.to_lowercase() == "transfer-encoding" && v.to_lowercase().contains("chunked")
    });

    let (encoded_body, consumed, incomplete) = if is_chunked {
        let (body, complete) = decode_chunked(data);
        let consumed = find_chunked_end(data);
        (Cow::Owned(body), consumed, !complete)
    } else if let Some(len) = content_length {
        let actual_len = len.min(data.len());
        (
            Cow::Borrowed(&data[..actual_len]),
            actual_len,
            actual_len < len,
        )
    } else {
        // delimited by connection close, so whatever was captured is the whole body
        (Cow::Borrowed(data), data.len(), false)
    };

    let (body, limit_exceeded) =
        decode_body_bounded(encoded_body.as_ref(), headers, max_body_bytes);

    ExtractedBody {
        body,
        consumed,
        encoded_size: encoded_body.len(),
        limit_exceeded,
        incomplete,
    }
}

fn find_chunked_end(data: &[u8]) -> usize {
    let mut pos = 0;

    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p);

        let Some(line_end) = line_end else {
            return data.len();
        };

        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);

        if size == 0 {
            return (line_end + 4).min(data.len());
        }

        let chunk_start = line_end + 2;
        let Some(chunk_end) = chunk_start.checked_add(size) else {
            return data.len();
        };
        let Some(next) = chunk_end.checked_add(2) else {
            return data.len();
        };
        pos = next;
    }

    data.len()
}

/// De-chunks `data`, reporting whether the terminating zero-size chunk was reached.
fn decode_chunked(data: &[u8]) -> (Vec<u8>, bool) {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p);

        let Some(line_end) = line_end else {
            break;
        };

        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        let size = match usize::from_str_radix(size_str.trim(), 16) {
            Ok(0) => return (result, true),
            Ok(size) => size,
            // an unparseable size line ends decoding without proving the body is complete
            Err(_) => break,
        };

        let chunk_start = line_end + 2;
        let Some(chunk_end) = chunk_start.checked_add(size) else {
            break;
        };

        if chunk_end > data.len() {
            break;
        }
        result.extend_from_slice(&data[chunk_start..chunk_end]);

        let Some(next) = chunk_end.checked_add(2) else {
            break;
        };
        pos = next;
    }

    (result, false)
}

fn read_bounded(mut decoder: impl Read, max_body_bytes: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut decompressed = Vec::new();
    let mut buffer = [0_u8; 8 << 10];

    loop {
        let remaining = max_body_bytes.saturating_sub(decompressed.len());
        let read_limit = if remaining == 0 {
            1
        } else {
            remaining.min(buffer.len())
        };
        let read = decoder.read(&mut buffer[..read_limit])?;
        if read == 0 {
            return Ok((decompressed, false));
        }
        if remaining == 0 {
            return Ok((decompressed, true));
        }
        decompressed.extend_from_slice(&buffer[..read]);
    }
}

fn decompress_bounded(
    coding: &str,
    data: &[u8],
    max_body_bytes: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    match coding {
        "gzip" | "x-gzip" => read_bounded(MultiGzDecoder::new(data), max_body_bytes),
        // RFC 9110 "deflate" is zlib-wrapped, but some servers send raw deflate.
        "deflate" => read_bounded(ZlibDecoder::new(data), max_body_bytes)
            .or_else(|_| read_bounded(DeflateDecoder::new(data), max_body_bytes)),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    }
}

pub(crate) fn copy_body_bounded(data: &[u8], max_body_bytes: usize) -> (Vec<u8>, bool) {
    let copied = data.len().min(max_body_bytes);
    (data[..copied].to_vec(), copied < data.len())
}

/// Undoes every `Content-Encoding` in reverse order of application. If any coding
/// is unsupported or fails to decode, the body is returned as captured.
pub(crate) fn decode_body_bounded(
    data: &[u8],
    headers: &[(String, String)],
    max_body_bytes: usize,
) -> (Vec<u8>, bool) {
    let codings: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty() && coding != "identity")
        .collect();

    let mut body = Cow::Borrowed(data);
    let mut limited = false;
    for coding in codings.iter().rev() {
        match decompress_bounded(coding, &body, max_body_bytes) {
            Ok((decoded, decoded_limited)) => {
                body = Cow::Owned(decoded);
                limited |= decoded_limited;
            }
            Err(_) => return copy_body_bounded(data, max_body_bytes),
        }
    }
    let (body, copy_limited) = copy_body_bounded(&body, max_body_bytes);
    (body, limited || copy_limited)
}

#[derive(Debug)]
pub struct HttpConversation {
    pub request: ParsedRequest,
    pub response: Option<ParsedResponse>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub request_timestamps: Vec<DateTime<Utc>>,
    pub response_timestamps: Vec<DateTime<Utc>>,
}

impl HttpConversation {
    pub fn start_time(&self) -> DateTime<Utc> {
        self.request_timestamps
            .first()
            .copied()
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp_nanos(0))
    }

    pub fn duration_ns(&self) -> i64 {
        let start = self.request_timestamps.first();
        let end = self
            .response_timestamps
            .last()
            .or(self.request_timestamps.last());

        match (start, end) {
            (Some(s), Some(e)) => (*e - *s).num_nanoseconds().unwrap_or(0),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn incompressible_fixture(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    #[test]
    fn test_parse_simple_request() {
        let data = b"GET / HTTP/1.1\r\nHost: localhost:3000\r\n\r\n";
        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "Host");
        assert_eq!(req.headers[0].1, "localhost:3000");
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_parse_request_with_query_string() {
        let data = b"GET /test.html?q=3&v=4 HTTP/1.1\r\nHost: localhost:3000\r\n\r\n";
        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/test.html?q=3&v=4");
        assert_eq!(req.version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_post_request_with_body() {
        let data = b"POST /api HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      Content-Length: 13\r\n\
                      Content-Type: application/json\r\n\
                      \r\n\
                      {\"key\":\"val\"}";

        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api");
        assert_eq!(req.body, b"{\"key\":\"val\"}");

        let has_content_type = req
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json");
        assert!(has_content_type);
    }

    #[test]
    fn test_parse_simple_response() {
        let data = b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      {}";

        let result = parse_response(data).unwrap();

        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.body, b"{}");

        let content_type = resp
            .headers
            .iter()
            .find(|(k, _)| k == "Content-Type")
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/json"));
    }

    #[test]
    fn gzip_limit_returns_decoded_prefix_when_encoded_input_exceeds_limit() {
        let original = incompressible_fixture(4 << 10);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() > 256);
        let mut message = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        message.extend_from_slice(&compressed);

        let (parsed, limited) = parse_response_bounded(&message, 256).unwrap();

        assert!(limited);
        assert_eq!(parsed.unwrap().body, original[..256]);
    }

    fn response_with_encoding(content_encoding: &str, body: &[u8]) -> Vec<u8> {
        let mut message = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: {content_encoding}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        message.extend_from_slice(body);
        message
    }

    #[test]
    fn deflate_bodies_are_decoded_whether_zlib_wrapped_or_raw() {
        use flate2::write::{DeflateEncoder, ZlibEncoder};
        let original = b"<html>deflated body</html>".repeat(20);
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(&original).unwrap();
        let mut raw = DeflateEncoder::new(Vec::new(), Compression::default());
        raw.write_all(&original).unwrap();

        for compressed in [zlib.finish().unwrap(), raw.finish().unwrap()] {
            let message = response_with_encoding("deflate", &compressed);
            let (parsed, limited) = parse_response_bounded(&message, usize::MAX).unwrap();
            assert!(!limited);
            assert_eq!(parsed.unwrap().body, original);
        }
    }

    #[test]
    fn stacked_content_encodings_are_decoded_in_reverse_order() {
        use flate2::write::ZlibEncoder;
        let original = b"stacked".repeat(50);
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(&original).unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&zlib.finish().unwrap()).unwrap();

        let message = response_with_encoding("Deflate, GZIP", &gzip.finish().unwrap());
        let (parsed, _) = parse_response_bounded(&message, usize::MAX).unwrap();

        assert_eq!(parsed.unwrap().body, original);
    }

    #[test]
    fn unsupported_or_corrupt_encodings_keep_the_captured_body() {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(b"payload").unwrap();
        let gzip = gzip.finish().unwrap();

        for (coding, body) in [
            ("br", &b"brotli bytes"[..]),
            ("br, gzip", &gzip[..]),
            ("gzip", b"not gzip"),
        ] {
            let message = response_with_encoding(coding, body);
            let (parsed, _) = parse_response_bounded(&message, usize::MAX).unwrap();
            assert_eq!(parsed.unwrap().body, body, "{coding}");
        }
    }

    #[test]
    fn test_parse_multiple_requests_keepalive() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /next HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";

        let requests = parse_all_requests(data);

        assert_eq!(requests.len(), 2, "Should parse 2 requests");
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/");
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[1].path, "/next");
    }

    #[test]
    fn test_parse_multiple_responses_keepalive() {
        let data = b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      {}\
                      HTTP/1.1 404 Not Found\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      --";

        let responses = parse_all_responses(data);

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].status, 200);
        assert_eq!(responses[0].reason, "OK");
        assert_eq!(responses[0].body, b"{}");
        assert_eq!(responses[1].status, 404);
        assert_eq!(responses[1].reason, "Not Found");
        assert_eq!(responses[1].body, b"--");
    }

    #[test]
    fn test_parse_chunked_response() {
        let data = b"HTTP/1.1 200 OK\r\n\
                      Transfer-Encoding: chunked\r\n\
                      \r\n\
                      5\r\n\
                      Hello\r\n\
                      6\r\n\
                      World!\r\n\
                      0\r\n\
                      \r\n";

        let result = parse_response(data).unwrap();

        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"HelloWorld!");
    }

    #[test]
    fn test_parse_request_with_multiple_headers() {
        let data = b"GET /api HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      User-Agent: test/1.0\r\n\
                      Accept: */*\r\n\
                      Authorization: Bearer token123\r\n\
                      \r\n";

        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.headers.len(), 4);

        let has_host = req.headers.iter().any(|(k, _)| k == "Host");
        let has_auth = req.headers.iter().any(|(k, _)| k == "Authorization");
        assert!(has_host);
        assert!(has_auth);
    }

    #[test]
    fn response_body_shorter_than_content_length_is_truncated() {
        let (resp, limited) = parse_response_bounded(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
            1 << 20,
        )
        .unwrap();
        let resp = resp.unwrap();

        assert_eq!(resp.body, b"short");
        assert_eq!(resp.encoded_body_size, 5);
        assert!(resp.body_truncated);
        assert!(!limited);
    }

    #[test]
    fn chunked_response_body_is_truncated_only_without_final_chunk() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let parse = |body: &[u8]| {
            let mut data = head.clone();
            data.extend_from_slice(body);
            parse_response_bounded(&data, 1 << 20).unwrap().0.unwrap()
        };

        let complete = parse(b"3\r\nfoo\r\n0\r\n\r\n");
        assert_eq!(complete.body, b"foo");
        assert!(!complete.body_truncated);

        let cut_mid_chunk = parse(b"3\r\nfoo\r\n5\r\nba");
        assert_eq!(cut_mid_chunk.body, b"foo");
        assert!(cut_mid_chunk.body_truncated);

        assert!(parse(b"3\r\nfoo\r\n").body_truncated);
    }

    #[test]
    fn gzip_response_reports_transferred_size_and_limit_truncation() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[b'x'; 4096]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut data = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        data.extend_from_slice(&compressed);

        let full = parse_response_bounded(&data, 1 << 20).unwrap().0.unwrap();
        assert_eq!(full.body.len(), 4096);
        assert_eq!(full.encoded_body_size, compressed.len());
        assert!(!full.body_truncated);

        let capped = parse_response_bounded(&data, 100).unwrap().0.unwrap();
        assert_eq!(capped.body.len(), 100);
        assert_eq!(capped.encoded_body_size, compressed.len());
        assert!(capped.body_truncated);
    }

    #[test]
    fn test_parse_incomplete_request() {
        let data = b"GET / HTTP/1.1\r\n";
        let result = parse_request(data);

        assert!(result.is_err());
        match result {
            Err(HttpError::Incomplete) => (),
            _ => panic!("Expected Incomplete error"),
        }
    }

    #[test]
    fn test_parse_invalid_request() {
        let data = b"INVALID DATA\r\n\r\n";
        let result = parse_request(data);

        assert!(result.is_err());
        match result {
            Err(HttpError::Parse(_)) => (),
            _ => panic!("Expected Parse error"),
        }
    }

    #[test]
    fn test_decode_chunked_multiple_chunks() {
        let data = b"3\r\n\
                     foo\r\n\
                     3\r\n\
                     bar\r\n\
                     4\r\n\
                     test\r\n\
                     0\r\n\
                     \r\n";

        let (result, complete) = decode_chunked(data);
        assert_eq!(result, b"foobartest");
        assert!(complete);
    }

    #[test]
    fn test_http_conversation_start_time() {
        let now = Utc::now();
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            request_timestamps: vec![now],
            response_timestamps: vec![],
        };

        assert_eq!(conv.start_time(), now);
    }

    #[test]
    fn http_conversation_without_timestamps_uses_epoch() {
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        assert_eq!(conv.start_time(), DateTime::<Utc>::from_timestamp_nanos(0));
    }

    #[test]
    fn test_http_conversation_duration() {
        use chrono::Duration;

        let start = Utc::now();
        let end = start + Duration::milliseconds(100);

        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            request_timestamps: vec![start],
            response_timestamps: vec![end],
        };

        let duration_ns = conv.duration_ns();
        assert!((99_000_000..=101_000_000).contains(&duration_ns));
    }

    #[test]
    fn test_parse_response_with_redirect() {
        let data = b"HTTP/1.1 301 Moved Permanently\r\n\
                      Location: https://example.com/new-location\r\n\
                      Content-Length: 0\r\n\
                      \r\n";

        let result = parse_response(data).unwrap();

        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status, 301);
        assert_eq!(resp.reason, "Moved Permanently");

        let location = resp
            .headers
            .iter()
            .find(|(k, _)| k == "Location")
            .map(|(_, v)| v.as_str());
        assert_eq!(location, Some("https://example.com/new-location"));
    }

    #[test]
    fn test_extract_body_with_content_length_larger_than_data() {
        let headers = vec![("Content-Length".to_string(), "1000".to_string())];
        let data = b"short body";

        let (body, consumed) = extract_body_with_length(data, &headers);
        assert_eq!(body, b"short body");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_request_with_form_data() {
        let data = b"POST /submit HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      Content-Type: application/x-www-form-urlencoded\r\n\
                      Content-Length: 29\r\n\
                      \r\n\
                      name=John&email=j%40e.com";

        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"name=John&email=j%40e.com");

        let content_type = req
            .headers
            .iter()
            .find(|(k, _)| k == "Content-Type")
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/x-www-form-urlencoded"));
    }
}
