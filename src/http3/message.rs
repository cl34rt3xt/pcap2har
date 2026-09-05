use crate::exchange::{NormalizedExchange, NormalizedRequest, NormalizedResponse};
use crate::quic::Direction;
use crate::DecodeLimits;
use std::collections::BTreeMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("HTTP/3 DATA arrived before initial headers")]
    DataBeforeHeaders,
    #[error("malformed HTTP/3 field section")]
    MalformedHeaders,
    #[error("HTTP/3 message exceeds configured limits")]
    LimitExceeded,
}

pub struct RequestStreamState {
    connection_sequence: u64,
    stream_id: u64,
    client: SocketAddr,
    server: SocketAddr,
    request_headers: Option<Vec<(String, String)>>,
    request_trailers: Vec<(String, String)>,
    request_body: Vec<u8>,
    informational: Vec<Vec<(String, String)>>,
    response_headers: Option<Vec<(String, String)>>,
    response_trailers: Vec<(String, String)>,
    response_body: Vec<u8>,
    client_fin: bool,
    server_fin: bool,
    first_timestamp_ns: u64,
    response_timestamp_ns: Option<u64>,
    end_timestamp_ns: u64,
    limits: DecodeLimits,
}

impl RequestStreamState {
    pub fn new(
        connection_sequence: u64,
        stream_id: u64,
        client: SocketAddr,
        server: SocketAddr,
        timestamp_ns: u64,
        limits: DecodeLimits,
    ) -> Self {
        Self {
            connection_sequence,
            stream_id,
            client,
            server,
            request_headers: None,
            request_trailers: Vec::new(),
            request_body: Vec::new(),
            informational: Vec::new(),
            response_headers: None,
            response_trailers: Vec::new(),
            response_body: Vec::new(),
            client_fin: false,
            server_fin: false,
            first_timestamp_ns: timestamp_ns,
            response_timestamp_ns: None,
            end_timestamp_ns: timestamp_ns,
            limits,
        }
    }

    pub fn apply_headers(
        &mut self,
        direction: Direction,
        fields: Vec<(Vec<u8>, Vec<u8>)>,
        timestamp_ns: u64,
    ) -> Result<(), MessageError> {
        let fields = validate_fields(fields, self.limits.max_header_section_bytes)?;
        self.end_timestamp_ns = self.end_timestamp_ns.max(timestamp_ns);
        match direction {
            Direction::ClientToServer if self.request_headers.is_none() => {
                validate_request_pseudo_headers(&fields)?;
                self.request_headers = Some(fields);
            }
            Direction::ClientToServer => {
                ensure_no_pseudo_headers(&fields)?;
                self.request_trailers.extend(fields);
            }
            Direction::ServerToClient => {
                if self.response_headers.is_some() {
                    ensure_no_pseudo_headers(&fields)?;
                    self.response_trailers.extend(fields);
                } else {
                    let status = response_status(&fields)?;
                    if (100..=199).contains(&status) {
                        self.informational.push(fields);
                    } else {
                        self.response_timestamp_ns.get_or_insert(timestamp_ns);
                        self.response_headers = Some(fields);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn apply_data(
        &mut self,
        direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> Result<(), MessageError> {
        self.end_timestamp_ns = self.end_timestamp_ns.max(timestamp_ns);
        let target = match direction {
            Direction::ClientToServer => {
                if self.request_headers.is_none() {
                    return Err(MessageError::DataBeforeHeaders);
                }
                &mut self.request_body
            }
            Direction::ServerToClient => {
                if self.response_headers.is_none() {
                    return Err(MessageError::DataBeforeHeaders);
                }
                &mut self.response_body
            }
        };
        let next = target
            .len()
            .checked_add(data.len())
            .ok_or(MessageError::LimitExceeded)?;
        if next > self.limits.max_body_bytes {
            return Err(MessageError::LimitExceeded);
        }
        target.extend_from_slice(data);
        Ok(())
    }

    pub fn finish_direction(&mut self, direction: Direction, timestamp_ns: u64) {
        match direction {
            Direction::ClientToServer => self.client_fin = true,
            Direction::ServerToClient => self.server_fin = true,
        }
        self.end_timestamp_ns = self.end_timestamp_ns.max(timestamp_ns);
    }

    pub fn is_complete(&self) -> bool {
        self.client_fin && self.server_fin && self.request_headers.is_some()
    }

    pub fn into_exchange(self) -> Result<NormalizedExchange, MessageError> {
        let request_fields = self.request_headers.ok_or(MessageError::MalformedHeaders)?;
        let request_map = pseudo_map(&request_fields);
        let method = request_map
            .get(":method")
            .cloned()
            .ok_or(MessageError::MalformedHeaders)?;
        let protocol = request_map.get(":protocol");
        let is_plain_connect = method == "CONNECT" && protocol.is_none();
        let scheme = if is_plain_connect {
            String::new()
        } else {
            request_map
                .get(":scheme")
                .cloned()
                .ok_or(MessageError::MalformedHeaders)?
        };
        let authority = request_map
            .get(":authority")
            .cloned()
            .ok_or(MessageError::MalformedHeaders)?;
        let path = if is_plain_connect {
            String::new()
        } else {
            request_map
                .get(":path")
                .cloned()
                .ok_or(MessageError::MalformedHeaders)?
        };
        let request_headers = regular_fields(&request_fields);
        let request_header_size = field_size(&request_fields);
        let response = self
            .response_headers
            .map(|fields| {
                let status = response_status(&fields)?;
                Ok(NormalizedResponse {
                    status,
                    reason: String::new(),
                    version: "HTTP/3".into(),
                    headers: regular_fields(&fields),
                    trailers: regular_fields(&self.response_trailers),
                    body: self.response_body,
                    header_size: field_size(&fields),
                })
            })
            .transpose()?;
        Ok(NormalizedExchange {
            connection_sequence: self.connection_sequence,
            stream_id: self.stream_id,
            client: self.client,
            server: self.server,
            request: NormalizedRequest {
                method,
                scheme,
                authority,
                path,
                version: "HTTP/3".into(),
                headers: request_headers,
                trailers: regular_fields(&self.request_trailers),
                body: self.request_body,
                header_size: request_header_size,
            },
            response,
            request_started_ns: self.first_timestamp_ns,
            response_started_ns: self.response_timestamp_ns,
            ended_ns: self.end_timestamp_ns,
        })
    }

    pub fn buffered_bytes(&self) -> usize {
        self.request_body.len()
            + self.response_body.len()
            + field_size(self.request_headers.as_deref().unwrap_or_default())
            + field_size(self.response_headers.as_deref().unwrap_or_default())
            + field_size(&self.request_trailers)
            + field_size(&self.response_trailers)
    }
}

fn validate_fields(
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    max_bytes: usize,
) -> Result<Vec<(String, String)>, MessageError> {
    let mut total = 0usize;
    let mut regular_seen = false;
    let mut pseudo_seen = BTreeMap::new();
    let mut output = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        total = total
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(MessageError::LimitExceeded)?;
        if total > max_bytes || name.is_empty() || name.iter().any(u8::is_ascii_uppercase) {
            return Err(MessageError::MalformedHeaders);
        }
        let name = String::from_utf8(name).map_err(|_| MessageError::MalformedHeaders)?;
        let value = String::from_utf8_lossy(&value).into_owned();
        if name.starts_with(':') {
            if regular_seen || pseudo_seen.insert(name.clone(), ()).is_some() {
                return Err(MessageError::MalformedHeaders);
            }
        } else {
            regular_seen = true;
        }
        output.push((name, value));
    }
    Ok(output)
}

fn validate_request_pseudo_headers(fields: &[(String, String)]) -> Result<(), MessageError> {
    let pseudo = pseudo_map(fields);
    let method = pseudo
        .get(":method")
        .ok_or(MessageError::MalformedHeaders)?;
    let authority = pseudo
        .get(":authority")
        .ok_or(MessageError::MalformedHeaders)?;
    if authority.is_empty() {
        return Err(MessageError::MalformedHeaders);
    }
    let extended_connect = method == "CONNECT" && pseudo.contains_key(":protocol");
    let plain_connect = method == "CONNECT" && !extended_connect;
    if !plain_connect && (!pseudo.contains_key(":scheme") || !pseudo.contains_key(":path")) {
        return Err(MessageError::MalformedHeaders);
    }
    for name in pseudo.keys() {
        if !matches!(
            name.as_str(),
            ":method" | ":scheme" | ":authority" | ":path" | ":protocol"
        ) {
            return Err(MessageError::MalformedHeaders);
        }
    }
    Ok(())
}

fn response_status(fields: &[(String, String)]) -> Result<u16, MessageError> {
    let pseudo = pseudo_map(fields);
    if pseudo.keys().any(|name| name != ":status") {
        return Err(MessageError::MalformedHeaders);
    }
    let status = pseudo
        .get(":status")
        .ok_or(MessageError::MalformedHeaders)?
        .parse::<u16>()
        .map_err(|_| MessageError::MalformedHeaders)?;
    if !(100..=599).contains(&status) {
        return Err(MessageError::MalformedHeaders);
    }
    Ok(status)
}

fn ensure_no_pseudo_headers(fields: &[(String, String)]) -> Result<(), MessageError> {
    if fields.iter().any(|(name, _)| name.starts_with(':')) {
        return Err(MessageError::MalformedHeaders);
    }
    Ok(())
}

fn pseudo_map(fields: &[(String, String)]) -> BTreeMap<String, String> {
    fields
        .iter()
        .filter(|(name, _)| name.starts_with(':'))
        .cloned()
        .collect()
}

fn regular_fields(fields: &[(String, String)]) -> Vec<(String, String)> {
    fields
        .iter()
        .filter(|(name, _)| !name.starts_with(':'))
        .cloned()
        .collect()
}

fn field_size(fields: &[(String, String)]) -> usize {
    fields
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn state() -> RequestStreamState {
        RequestStreamState::new(
            1,
            0,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            1,
            DecodeLimits::testing(),
        )
    }

    fn fields(values: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        values
            .iter()
            .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn builds_http3_exchange_from_both_directions() {
        let mut state = state();
        state
            .apply_headers(
                Direction::ClientToServer,
                fields(&[
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", "example.test"),
                    (":path", "/upload"),
                    ("content-type", "text/plain"),
                ]),
                1,
            )
            .unwrap();
        state
            .apply_data(Direction::ClientToServer, b"request", 2)
            .unwrap();
        state
            .apply_headers(
                Direction::ServerToClient,
                fields(&[(":status", "200"), ("server", "test")]),
                3,
            )
            .unwrap();
        state
            .apply_data(Direction::ServerToClient, b"response", 4)
            .unwrap();
        let exchange = state.into_exchange().unwrap();
        assert_eq!(exchange.request.path, "/upload");
        assert_eq!(exchange.request.body, b"request");
        assert_eq!(exchange.response.unwrap().body, b"response");
    }
}
