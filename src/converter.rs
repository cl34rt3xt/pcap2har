use crate::exchange::{NormalizedExchange, NormalizedRequest, NormalizedResponse};
use crate::fcgi::{
    fcgi_to_http_request_bounded, fcgi_to_http_response_bounded, parse_fcgi_request,
    parse_fcgi_response,
};
use crate::har::{
    BodySummary, Cache, Content, Cookie, Entry, Har, Header, Param, PostData, QueryParam, Request,
    Response, Timings,
};
use crate::http::{
    copy_body_bounded, parse_all_requests_bounded, parse_all_responses_bounded,
    parse_request_bounded, parse_response_bounded, HttpConversation, ParsedRequest, ParsedResponse,
};
use crate::http2::{is_http2, parse_http2_frames, parse_http2_stream, Http2Request, Http2Response};
use crate::tcp::{StreamKey, TcpStream};
use crate::tls::{
    decrypt_tls12_record, decrypt_tls13_record_full, derive_tls12_keys, extract_cipher_suite,
    extract_client_random, extract_server_random, parse_tls_records, CipherSuiteInfo, TlsSecrets,
};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use url::Url;

pub struct Converter {
    exchanges: Vec<NormalizedExchange>,
    tcp_exchange_indices: Vec<usize>,
    max_body_bytes: usize,
    remaining_body_bytes: usize,
    body_limit_exceeded: bool,
    body_summary_bytes: Option<usize>,
}

impl Converter {
    pub fn new() -> Self {
        Self::with_limits(&crate::DecodeLimits::default())
    }

    pub(crate) fn with_limits(limits: &crate::DecodeLimits) -> Self {
        Converter {
            exchanges: Vec::new(),
            tcp_exchange_indices: Vec::new(),
            max_body_bytes: limits.max_body_bytes,
            remaining_body_bytes: limits.max_total_buffered_bytes,
            body_limit_exceeded: false,
            body_summary_bytes: None,
        }
    }

    /// Emit a `BodySummary` (hashes and the first `prefix_bytes`) in place of body text.
    pub(crate) fn set_body_summary(&mut self, prefix_bytes: Option<usize>) {
        self.body_summary_bytes = prefix_bytes;
    }

    pub(crate) fn body_limit_exceeded(&self) -> bool {
        self.body_limit_exceeded
    }

    fn available_body_bytes(&self) -> usize {
        self.max_body_bytes.min(self.remaining_body_bytes)
    }

    fn account_body(&mut self, body_bytes: usize, limit_exceeded: bool) {
        self.body_limit_exceeded |= limit_exceeded || body_bytes > self.remaining_body_bytes;
        self.remaining_body_bytes = self.remaining_body_bytes.saturating_sub(body_bytes);
    }

    pub fn add_exchange(&mut self, exchange: NormalizedExchange) {
        self.exchanges.push(exchange);
    }

    fn add_conversation(
        &mut self,
        conversation: HttpConversation,
        scheme: &str,
        authority: Option<&str>,
        stream_id: u64,
    ) {
        let exchange_index = self.exchanges.len();
        self.exchanges.push(normalize_conversation(
            conversation,
            scheme,
            authority,
            stream_id,
        ));
        self.tcp_exchange_indices.push(exchange_index);
    }

    pub fn process_streams(&mut self, streams: HashMap<StreamKey, TcpStream>) {
        let mut request_streams: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, Vec<ParsedRequest>),
        > = HashMap::new();
        let mut response_streams: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, Vec<ParsedResponse>),
        > = HashMap::new();

        let mut ordered_streams: Vec<_> = streams.iter().collect();
        ordered_streams.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (key, stream) in ordered_streams {
            let (data, timestamps) = stream.reassemble();
            if data.is_empty() {
                continue;
            }

            let (requests, limited) =
                parse_all_requests_bounded(&data, self.max_body_bytes, self.remaining_body_bytes);
            if !requests.is_empty() {
                for request in &requests {
                    self.account_body(request.body.len(), limited);
                }
                request_streams.insert(key.clone(), (timestamps.clone(), requests));
                continue;
            }

            let (responses, limited) =
                parse_all_responses_bounded(&data, self.max_body_bytes, self.remaining_body_bytes);
            if !responses.is_empty() {
                for response in &responses {
                    self.account_body(response.body.len(), limited);
                }
                response_streams.insert(key.clone(), (timestamps.clone(), responses));
                continue;
            }

            if let Some(fcgi_req) = parse_fcgi_request(&data) {
                let (request, limited) =
                    fcgi_to_http_request_bounded(&fcgi_req, self.available_body_bytes());
                if let Some(req) = request {
                    self.account_body(req.body.len(), limited);
                    request_streams.insert(key.clone(), (timestamps.clone(), vec![req]));
                    continue;
                }
            }

            if let Some(fcgi_resp) = parse_fcgi_response(&data) {
                let (response, limited) =
                    fcgi_to_http_response_bounded(&fcgi_resp, self.available_body_bytes());
                if let Some(resp) = response {
                    self.account_body(resp.body.len(), limited);
                    response_streams.insert(key.clone(), (timestamps.clone(), vec![resp]));
                }
            }
        }

        for (req_key, (req_timestamps, requests)) in &request_streams {
            let resp_key = req_key.reverse();
            let response_data = response_streams.get(&resp_key);

            let responses = response_data
                .map(|(_, resps)| resps.as_slice())
                .unwrap_or(&[]);
            let resp_timestamps = response_data.map(|(ts, _)| ts.clone()).unwrap_or_default();

            for (i, request) in requests.iter().enumerate() {
                let response = responses.get(i).cloned();

                let conversation = HttpConversation {
                    request: request.clone(),
                    response,
                    src_ip: req_key.src_ip.to_string(),
                    dst_ip: req_key.dst_ip.to_string(),
                    src_port: req_key.src_port,
                    dst_port: req_key.dst_port,
                    request_timestamps: req_timestamps.clone(),
                    response_timestamps: resp_timestamps.clone(),
                };

                self.add_conversation(conversation, "http", None, 0);
            }
        }
    }

    pub fn process_streams_with_tls(
        &mut self,
        streams: HashMap<StreamKey, TcpStream>,
        tls_secrets: &TlsSecrets,
    ) {
        let mut tls_streams: HashMap<StreamKey, (Vec<u8>, Vec<chrono::DateTime<chrono::Utc>>)> =
            HashMap::new();
        let mut client_randoms: HashMap<StreamKey, String> = HashMap::new();
        let mut server_randoms: HashMap<StreamKey, String> = HashMap::new();
        let mut cipher_suites: HashMap<StreamKey, u16> = HashMap::new();

        let mut ordered_streams: Vec<_> = streams.iter().collect();
        ordered_streams.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (key, stream) in ordered_streams {
            let (data, timestamps) = stream.reassemble();
            if data.is_empty() {
                continue;
            }

            if is_tls_data(&data) {
                let records = parse_tls_records(&data);
                for record in &records {
                    if record.content_type == 22 {
                        if let Some(random) = extract_client_random(&record.payload) {
                            client_randoms.insert(key.clone(), random);
                        }
                        if let Some(random) = extract_server_random(&record.payload) {
                            server_randoms.insert(key.clone(), random);
                        }
                        if let Some(suite) = extract_cipher_suite(&record.payload) {
                            cipher_suites.insert(key.clone(), suite);
                        }
                    }
                }
                tls_streams.insert(key.clone(), (data, timestamps));
            }
        }

        let mut decrypted_streams: HashMap<
            StreamKey,
            (Vec<u8>, Vec<chrono::DateTime<chrono::Utc>>),
        > = HashMap::new();
        for (key, (data, timestamps)) in &tls_streams {
            let reverse = key.reverse();
            let client_random = client_randoms
                .get(key)
                .or_else(|| client_randoms.get(&reverse));

            let Some(random) = client_random else {
                continue;
            };
            let is_client = client_randoms.contains_key(key);
            if let Some(secrets) = tls_secrets.traffic_secrets.get(random) {
                let secret = if is_client {
                    secrets.client_traffic_secret_0.as_ref()
                } else {
                    secrets.server_traffic_secret_0.as_ref()
                };

                if let Some(secret) = secret {
                    if let Some(decrypted) = self.decrypt_tls13_stream(data, secret) {
                        decrypted_streams.insert(key.clone(), (decrypted, timestamps.clone()));
                    }
                }
            } else if let Some(master_secret) = tls_secrets
                .client_randoms
                .get(random)
                .and_then(|secrets| secrets.master_secret.as_deref())
            {
                let server_random_hex = if is_client {
                    server_randoms.get(&reverse)
                } else {
                    server_randoms.get(key)
                };

                let cipher_suite = if is_client {
                    cipher_suites.get(&reverse).copied()
                } else {
                    cipher_suites.get(key).copied()
                };

                if let (Some(server_random_hex), Some(suite)) = (server_random_hex, cipher_suite) {
                    if let Some(cipher_info) = CipherSuiteInfo::from_id(suite) {
                        if let Some(decrypted) = self.decrypt_tls12_stream(
                            data,
                            master_secret,
                            random,
                            server_random_hex,
                            &cipher_info,
                            is_client,
                        ) {
                            decrypted_streams.insert(key.clone(), (decrypted, timestamps.clone()));
                        }
                    }
                }
            }
        }

        let mut request_streams: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, ParsedRequest),
        > = HashMap::new();
        let mut response_streams: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, ParsedResponse),
        > = HashMap::new();
        let mut h2_requests: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, Vec<Http2Request>),
        > = HashMap::new();
        let mut h2_responses: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, Vec<Http2Response>),
        > = HashMap::new();

        let mut ordered_decrypted_streams: Vec<_> = decrypted_streams.iter().collect();
        ordered_decrypted_streams.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (key, (data, timestamps)) in ordered_decrypted_streams {
            if is_http2(data) {
                let frames = parse_http2_frames(data);
                let is_client = client_randoms.contains_key(key);
                let (reqs, resps) = parse_http2_stream(&frames, is_client);

                if is_client && !reqs.is_empty() {
                    h2_requests.insert(key.clone(), (timestamps.clone(), reqs));
                } else if !is_client && !resps.is_empty() {
                    h2_responses.insert(key.clone(), (timestamps.clone(), resps));
                }
            } else if let Ok((Some(req), limited)) =
                parse_request_bounded(data, self.available_body_bytes())
            {
                self.account_body(req.body.len(), limited);
                request_streams.insert(key.clone(), (timestamps.clone(), req));
            } else if let Ok((Some(resp), limited)) =
                parse_response_bounded(data, self.available_body_bytes())
            {
                self.account_body(resp.body.len(), limited);
                response_streams.insert(key.clone(), (timestamps.clone(), resp));
            }
        }

        for (req_key, (req_timestamps, request)) in &request_streams {
            let resp_key = req_key.reverse();
            let response_data = response_streams.remove(&resp_key);

            let conversation = HttpConversation {
                request: request.clone(),
                response: response_data.as_ref().map(|(_, resp)| resp.clone()),
                src_ip: req_key.src_ip.to_string(),
                dst_ip: req_key.dst_ip.to_string(),
                src_port: req_key.src_port,
                dst_port: req_key.dst_port,
                request_timestamps: req_timestamps.clone(),
                response_timestamps: response_data.map(|(ts, _)| ts).unwrap_or_default(),
            };

            self.add_conversation(conversation, "https", None, 0);
        }

        let mut ordered_h2_requests: Vec<_> = h2_requests.into_iter().collect();
        ordered_h2_requests.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (req_key, (req_timestamps, requests)) in ordered_h2_requests {
            let resp_key = req_key.reverse();
            let response_data = h2_responses.remove(&resp_key);

            for h2_req in requests {
                let h2_resp = response_data
                    .as_ref()
                    .and_then(|(_, resps)| resps.iter().find(|r| r.stream_id == h2_req.stream_id));

                let mut headers = h2_req.headers.clone();
                if !h2_req.authority.is_empty() {
                    headers.push(("host".to_string(), h2_req.authority.clone()));
                }

                let (request_body, request_limited) =
                    copy_body_bounded(&h2_req.body, self.available_body_bytes());
                self.account_body(request_body.len(), request_limited);
                let parsed_req = ParsedRequest {
                    method: h2_req.method.clone(),
                    path: h2_req.path.clone(),
                    version: "HTTP/2".to_string(),
                    headers,
                    body: request_body,
                    header_size: 0,
                };

                let parsed_resp = h2_resp.map(|r| {
                    let (body, limited) = copy_body_bounded(&r.body, self.available_body_bytes());
                    self.account_body(body.len(), limited);
                    ParsedResponse {
                        version: "HTTP/2".to_string(),
                        status: r.status,
                        reason: String::new(),
                        headers: r.headers.clone(),
                        body,
                        header_size: 0,
                        encoded_body_size: r.body.len(),
                        body_truncated: limited,
                    }
                });

                let conversation = HttpConversation {
                    request: parsed_req,
                    response: parsed_resp,
                    src_ip: req_key.src_ip.to_string(),
                    dst_ip: req_key.dst_ip.to_string(),
                    src_port: req_key.src_port,
                    dst_port: req_key.dst_port,
                    request_timestamps: req_timestamps.clone(),
                    response_timestamps: response_data
                        .as_ref()
                        .map(|(ts, _)| ts.clone())
                        .unwrap_or_default(),
                };

                let scheme = if h2_req.scheme.is_empty() {
                    "https"
                } else {
                    &h2_req.scheme
                };
                self.add_conversation(
                    conversation,
                    scheme,
                    Some(&h2_req.authority),
                    u64::from(h2_req.stream_id),
                );
            }
        }

        let non_tls_streams: HashMap<StreamKey, TcpStream> = streams
            .into_iter()
            .filter(|(key, _)| !tls_streams.contains_key(key))
            .collect();

        self.process_streams(non_tls_streams);
    }

    fn decrypt_tls13_stream(&self, data: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
        let records = parse_tls_records(data);
        let app_records: Vec<_> = records.iter().filter(|r| r.content_type == 23).collect();

        if app_records.is_empty() {
            return None;
        }

        // Try different skip values - first records may use handshake keys
        for skip in 0..app_records.len().min(6) {
            let mut decrypted = Vec::new();
            let mut success = true;

            for (i, record) in app_records.iter().skip(skip).enumerate() {
                if let Some(result) =
                    decrypt_tls13_record_full(&record.payload, secret, i as u64, record.length)
                {
                    if result.content_type == 23 {
                        decrypted.extend_from_slice(&result.data);
                    }
                } else {
                    if !decrypted.is_empty() {
                        break; // Got some data before failure
                    }
                    success = false;
                    break;
                }
            }

            if (success || !decrypted.is_empty()) && !decrypted.is_empty() {
                return Some(decrypted);
            }
        }

        None
    }

    fn decrypt_tls12_stream(
        &self,
        data: &[u8],
        master_secret: &[u8],
        client_random_hex: &str,
        server_random_hex: &str,
        cipher_info: &CipherSuiteInfo,
        is_client: bool,
    ) -> Option<Vec<u8>> {
        let client_random = hex::decode(client_random_hex).ok()?;
        let server_random = hex::decode(server_random_hex).ok()?;

        let keys = derive_tls12_keys(master_secret, &client_random, &server_random, cipher_info);

        let (write_key, write_iv) = if is_client {
            (&keys.client_write_key, &keys.client_write_iv)
        } else {
            (&keys.server_write_key, &keys.server_write_iv)
        };

        let records = parse_tls_records(data);
        let app_records: Vec<_> = records.iter().filter(|r| r.content_type == 23).collect();

        let mut decrypted = Vec::new();

        for (i, record) in app_records.iter().enumerate() {
            let seq = (i + 1) as u64;
            if let Some(plaintext) =
                decrypt_tls12_record(&record.payload, write_key, write_iv, seq, 23)
            {
                decrypted.extend_from_slice(&plaintext);
            } else {
                break;
            }
        }

        if decrypted.is_empty() {
            None
        } else {
            Some(decrypted)
        }
    }

    pub fn to_har(mut self) -> Har {
        assign_tcp_connection_sequences(&mut self.exchanges, &self.tcp_exchange_indices);
        exchanges_to_har(self.exchanges, self.body_summary_bytes)
    }

    fn exchange_to_entry(&self, exchange: &NormalizedExchange) -> Entry {
        let url = self.build_url(&exchange.request);
        let request = self.build_request(&exchange.request, &url);
        let response = self.build_response(exchange.response.as_ref(), &exchange.request.version);
        let duration = exchange
            .ended_ns
            .saturating_sub(exchange.request_started_ns);

        Entry {
            pageref: String::new(),
            started_date_time: timestamp_to_datetime(exchange.request_started_ns),
            time: i64::try_from(duration).unwrap_or(i64::MAX),
            request,
            response,
            cache: Cache {},
            timings: Timings::default(),
            server_ip_address: Some(exchange.server.ip().to_string()),
            connection: Some(format!("{}->{}", exchange.client, exchange.server)),
        }
    }

    fn build_url(&self, request: &NormalizedRequest) -> String {
        format!(
            "{}://{}{}",
            request.scheme,
            normalize_authority(&request.authority, &request.scheme),
            request.path
        )
    }

    fn build_request(&self, req: &NormalizedRequest, url: &str) -> Request {
        let headers: Vec<Header> = req
            .headers
            .iter()
            .chain(&req.trailers)
            .map(|(k, v)| Header {
                name: k.clone(),
                value: v.clone(),
            })
            .collect();

        let cookies = self.parse_cookies(&req.headers);
        let query_string = self.parse_query_string(url);
        let post_data = self.parse_post_data(req);

        Request {
            method: req.method.clone(),
            url: url.to_string(),
            http_version: req.version.clone(),
            cookies,
            headers,
            query_string,
            post_data,
            headers_size: req.header_size as i64,
            body_size: req.body.len() as i64,
        }
    }

    fn build_response(&self, resp: Option<&NormalizedResponse>, request_version: &str) -> Response {
        match resp {
            Some(resp) => {
                let headers: Vec<Header> = resp
                    .headers
                    .iter()
                    .chain(&resp.trailers)
                    .map(|(k, v)| Header {
                        name: k.clone(),
                        value: v.clone(),
                    })
                    .collect();

                let cookies = self.parse_set_cookies(&resp.headers);
                let content = self.build_content(resp);

                let redirect_url = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == "location")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();

                Response {
                    status: resp.status,
                    status_text: resp.reason.clone(),
                    http_version: resp.version.clone(),
                    cookies,
                    headers,
                    content,
                    redirect_url,
                    headers_size: resp.header_size as i64,
                    body_size: resp.encoded_body_size as i64,
                }
            }
            None => Response {
                status: 0,
                status_text: String::new(),
                http_version: request_version.to_string(),
                cookies: Vec::new(),
                headers: Vec::new(),
                content: Content {
                    size: 0,
                    compression: None,
                    mime_type: String::new(),
                    text: None,
                    encoding: None,
                    truncated: false,
                    summary: None,
                },
                redirect_url: String::new(),
                headers_size: -1,
                body_size: -1,
            },
        }
    }

    fn build_content(&self, resp: &NormalizedResponse) -> Content {
        let mime_type = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
            .unwrap_or_default();

        // Text-like bodies are only emitted as text when that is lossless; anything
        // else is base64 so the decoded HAR content matches the body bytes exactly.
        let utf8_text = is_text_content(&mime_type)
            .then(|| std::str::from_utf8(&resp.body).ok())
            .flatten();
        if let Some(prefix_bytes) = self.body_summary_bytes {
            return Content {
                size: resp.body.len() as i64,
                compression: None,
                mime_type,
                text: None,
                encoding: None,
                truncated: resp.body_truncated,
                summary: Some(BodySummary::of(&resp.body, prefix_bytes)),
            };
        }
        let (text, encoding) = if resp.body.is_empty() {
            (Some(String::new()), None)
        } else if let Some(text) = utf8_text {
            (Some(text.to_string()), None)
        } else {
            use base64::{engine::general_purpose::STANDARD, Engine};
            (
                Some(STANDARD.encode(&resp.body)),
                Some("base64".to_string()),
            )
        };

        Content {
            size: resp.body.len() as i64,
            compression: None,
            mime_type,
            text,
            encoding,
            truncated: resp.body_truncated,
            summary: None,
        }
    }

    fn parse_cookies(&self, headers: &[(String, String)]) -> Vec<Cookie> {
        headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "cookie")
            .flat_map(|(_, v)| {
                v.split(';').filter_map(|cookie| {
                    let mut parts = cookie.trim().splitn(2, '=');
                    let name = parts.next()?.to_string();
                    let value = parts.next().unwrap_or("").to_string();
                    Some(Cookie {
                        name,
                        value,
                        path: None,
                        domain: None,
                        expires: None,
                        http_only: None,
                        secure: None,
                    })
                })
            })
            .collect()
    }

    fn parse_set_cookies(&self, headers: &[(String, String)]) -> Vec<Cookie> {
        headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "set-cookie")
            .filter_map(|(_, v)| {
                let mut parts = v.split(';');
                let main_part = parts.next()?;
                let mut kv = main_part.splitn(2, '=');
                let name = kv.next()?.trim().to_string();
                let value = kv.next().unwrap_or("").trim().to_string();

                let mut cookie = Cookie {
                    name,
                    value,
                    path: None,
                    domain: None,
                    expires: None,
                    http_only: None,
                    secure: None,
                };

                for attr in parts {
                    let attr = attr.trim().to_lowercase();
                    if attr == "httponly" {
                        cookie.http_only = Some(true);
                    } else if attr == "secure" {
                        cookie.secure = Some(true);
                    } else if let Some(path) = attr.strip_prefix("path=") {
                        cookie.path = Some(path.to_string());
                    } else if let Some(domain) = attr.strip_prefix("domain=") {
                        cookie.domain = Some(domain.to_string());
                    } else if let Some(expires) = attr.strip_prefix("expires=") {
                        cookie.expires = Some(expires.to_string());
                    }
                }

                Some(cookie)
            })
            .collect()
    }

    fn parse_query_string(&self, url: &str) -> Vec<QueryParam> {
        Url::parse(url)
            .map(|u| {
                u.query_pairs()
                    .map(|(k, v)| QueryParam {
                        name: k.to_string(),
                        value: v.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_post_data(&self, req: &NormalizedRequest) -> Option<PostData> {
        if req.body.is_empty() {
            return None;
        }

        let content_type = req
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        let mime_type = content_type.split(';').next().unwrap_or("").trim();

        if let Some(prefix_bytes) = self.body_summary_bytes {
            return Some(PostData {
                mime_type: mime_type.to_string(),
                text: None,
                params: None,
                summary: Some(BodySummary::of(&req.body, prefix_bytes)),
            });
        }

        if mime_type == "application/x-www-form-urlencoded" {
            let text = String::from_utf8_lossy(&req.body);
            let params: Vec<Param> = text
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let name = parts.next()?.to_string();
                    let value = parts.next().map(|s| s.to_string());
                    Some(Param {
                        name,
                        value,
                        file_name: None,
                        content_type: None,
                    })
                })
                .collect();

            Some(PostData {
                mime_type: mime_type.to_string(),
                text: Some(text.to_string()),
                params: Some(params),
                summary: None,
            })
        } else {
            Some(PostData {
                mime_type: mime_type.to_string(),
                text: Some(String::from_utf8_lossy(&req.body).to_string()),
                params: None,
                summary: None,
            })
        }
    }
}

fn normalize_conversation(
    conversation: HttpConversation,
    scheme: &str,
    authority: Option<&str>,
    stream_id: u64,
) -> NormalizedExchange {
    let client_ip = conversation
        .src_ip
        .parse::<IpAddr>()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let server_ip = conversation
        .dst_ip
        .parse::<IpAddr>()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let client = SocketAddr::new(client_ip, conversation.src_port);
    let server = SocketAddr::new(server_ip, conversation.dst_port);
    let (target_authority, path) = match split_absolute_form(&conversation.request.path) {
        Some((target_authority, path)) => (Some(target_authority), path),
        None => (None, conversation.request.path),
    };
    let authority = authority
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or(target_authority)
        .or_else(|| {
            conversation
                .request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.clone())
        })
        .unwrap_or_else(|| authority_from_server(server, scheme));
    let request_started_ns = conversation
        .request_timestamps
        .first()
        .and_then(datetime_to_timestamp)
        .unwrap_or_default();
    let response_started_ns = conversation
        .response_timestamps
        .first()
        .and_then(datetime_to_timestamp);
    let ended_ns = conversation
        .response_timestamps
        .last()
        .or_else(|| conversation.request_timestamps.last())
        .and_then(datetime_to_timestamp)
        .unwrap_or(request_started_ns);

    NormalizedExchange {
        connection_sequence: 0,
        stream_id,
        client,
        server,
        request: NormalizedRequest {
            method: conversation.request.method,
            scheme: scheme.to_string(),
            authority,
            path,
            version: conversation.request.version,
            headers: conversation.request.headers,
            trailers: Vec::new(),
            body: conversation.request.body,
            header_size: conversation.request.header_size,
        },
        response: conversation.response.map(|response| NormalizedResponse {
            status: response.status,
            reason: response.reason,
            version: response.version,
            headers: response.headers,
            trailers: Vec::new(),
            body: response.body,
            header_size: response.header_size,
            encoded_body_size: response.encoded_body_size,
            body_truncated: response.body_truncated,
        }),
        request_started_ns,
        response_started_ns,
        ended_ns,
    }
}

fn datetime_to_timestamp(value: &DateTime<Utc>) -> Option<u64> {
    value
        .timestamp_nanos_opt()
        .and_then(|ns| u64::try_from(ns).ok())
}

fn timestamp_to_datetime(value: u64) -> DateTime<Utc> {
    DateTime::from_timestamp_nanos(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Splits an absolute-form request target (`GET http://host/path`, as sent to proxies) into
/// its authority and origin-form path. RFC 9112 3.2.2: the target's authority then takes
/// precedence over the Host header.
fn split_absolute_form(target: &str) -> Option<(String, String)> {
    let rest = ["http://", "https://"].iter().find_map(|prefix| {
        target
            .get(..prefix.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(prefix))
            .map(|_| &target[prefix.len()..])
    })?;
    let (authority, path) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Some((authority.to_string(), path))
}

/// Normalizes an authority for use in a URL: drops userinfo, lowercases the host and
/// removes a port that is the scheme's default, as URL parsers do.
fn normalize_authority(authority: &str, scheme: &str) -> String {
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host_port = host_port.to_ascii_lowercase();
    let default_port = match scheme {
        "http" => Some(":80"),
        "https" => Some(":443"),
        _ => None,
    };
    let host_port = match default_port {
        Some(port) if host_port.ends_with(port) => &host_port[..host_port.len() - port.len()],
        _ => host_port.strip_suffix(':').unwrap_or(&host_port),
    };
    host_port.to_string()
}

fn authority_from_server(server: SocketAddr, scheme: &str) -> String {
    let host = match server.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let is_default_port =
        (scheme == "http" && server.port() == 80) || (scheme == "https" && server.port() == 443);
    if is_default_port {
        host
    } else {
        format!("{host}:{}", server.port())
    }
}

fn assign_tcp_connection_sequences(
    exchanges: &mut [NormalizedExchange],
    tcp_exchange_indices: &[usize],
) {
    let endpoints = tcp_exchange_indices
        .iter()
        .filter_map(|index| exchanges.get(*index))
        .map(|exchange| (exchange.client, exchange.server))
        .collect::<BTreeSet<_>>();
    let sequences = endpoints
        .into_iter()
        .enumerate()
        .map(|(sequence, endpoints)| (endpoints, u64::try_from(sequence).unwrap_or(u64::MAX)))
        .collect::<BTreeMap<_, _>>();

    for index in tcp_exchange_indices {
        if let Some(exchange) = exchanges.get_mut(*index) {
            exchange.connection_sequence = sequences
                .get(&(exchange.client, exchange.server))
                .copied()
                .unwrap_or(u64::MAX);
        }
    }
}

pub fn normalized_exchanges_to_har(exchanges: Vec<NormalizedExchange>) -> Har {
    exchanges_to_har(exchanges, None)
}

fn exchanges_to_har(
    mut exchanges: Vec<NormalizedExchange>,
    body_summary_bytes: Option<usize>,
) -> Har {
    exchanges.sort_by(|left, right| {
        left.request_started_ns
            .cmp(&right.request_started_ns)
            .then_with(|| left.connection_sequence.cmp(&right.connection_sequence))
            .then_with(|| left.stream_id.cmp(&right.stream_id))
            .then_with(|| left.cmp(right))
    });

    let mut converter = Converter::new();
    converter.set_body_summary(body_summary_bytes);
    let mut har = Har::new();
    for exchange in &exchanges {
        har.add_entry(converter.exchange_to_entry(exchange));
    }
    har
}

impl Default for Converter {
    fn default() -> Self {
        Self::new()
    }
}

fn is_text_content(mime_type: &str) -> bool {
    mime_type.starts_with("text/")
        || mime_type.contains("json")
        || mime_type.contains("xml")
        || mime_type.contains("javascript")
        || mime_type.contains("html")
}

fn is_tls_data(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let content_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];

    (20..=23).contains(&content_type) && version_major == 3 && version_minor <= 3
}

pub fn convert_pcap_to_har(pcap_path: &str) -> Result<Har, crate::tcp::TcpError> {
    crate::convert_capture(
        std::path::Path::new(pcap_path),
        crate::ConversionOptions::default(),
    )
    .map(|report| report.har)
    .map_err(|_| crate::tcp::TcpError::Parse("capture conversion failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ParsedRequest, ParsedResponse};
    use chrono::Utc;

    fn normalized_request(request: ParsedRequest) -> NormalizedRequest {
        NormalizedRequest {
            method: request.method,
            scheme: "http".to_string(),
            authority: "example.test".to_string(),
            path: request.path,
            version: request.version,
            headers: request.headers,
            trailers: Vec::new(),
            body: request.body,
            header_size: request.header_size,
        }
    }

    fn normalized_response(response: ParsedResponse) -> NormalizedResponse {
        NormalizedResponse {
            status: response.status,
            reason: response.reason,
            version: response.version,
            headers: response.headers,
            trailers: Vec::new(),
            body: response.body,
            header_size: response.header_size,
            encoded_body_size: response.encoded_body_size,
            body_truncated: response.body_truncated,
        }
    }

    #[test]
    fn test_converter_new() {
        let converter = Converter::new();
        assert_eq!(converter.exchanges.len(), 0);
    }

    #[test]
    fn test_build_url_with_host_header() {
        let converter = Converter::new();
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/api/data".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![("Host".to_string(), "example.com".to_string())],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 80,
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        let exchange = normalize_conversation(conv, "http", None, 0);
        let url = converter.build_url(&exchange.request);
        assert_eq!(url, "http://example.com/api/data");
    }

    fn url_for(path: &str, host: Option<&str>) -> String {
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: path.to_string(),
                version: "HTTP/1.1".to_string(),
                headers: host
                    .map(|host| vec![("Host".to_string(), host.to_string())])
                    .unwrap_or_default(),
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 80,
            request_timestamps: vec![],
            response_timestamps: vec![],
        };
        Converter::new().build_url(&normalize_conversation(conv, "http", None, 0).request)
    }

    #[test]
    fn absolute_form_target_supplies_authority_and_path() {
        assert_eq!(
            url_for("http://Proxy.Example.com/a?b=1", Some("other.example")),
            "http://proxy.example.com/a?b=1"
        );
        assert_eq!(url_for("HTTP://example.com", None), "http://example.com/");
        assert_eq!(
            url_for("http://example.com?x", None),
            "http://example.com/?x"
        );
    }

    #[test]
    fn authority_is_normalized_like_a_url_parser() {
        assert_eq!(
            url_for("/p", Some("Example.COM:80")),
            "http://example.com/p"
        );
        assert_eq!(
            url_for("/p", Some("example.com:8080")),
            "http://example.com:8080/p"
        );
        assert_eq!(url_for("/p", Some("example.com:")), "http://example.com/p");
        assert_eq!(
            url_for("/p", Some("[2001:DB8::1]:80")),
            "http://[2001:db8::1]/p"
        );
        assert_eq!(
            url_for("/Path/Case", Some("example.com")),
            "http://example.com/Path/Case"
        );
    }

    #[test]
    fn test_build_url_https_port() {
        let converter = Converter::new();
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/secure".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![("Host".to_string(), "secure.example.com".to_string())],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 443, // HTTPS port
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        let exchange = normalize_conversation(conv, "https", None, 0);
        let url = converter.build_url(&exchange.request);
        assert_eq!(url, "https://secure.example.com/secure");
    }

    #[test]
    fn test_build_url_without_host_header() {
        let converter = Converter::new();
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
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 54321,
            dst_port: 8080,
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        let exchange = normalize_conversation(conv, "http", None, 0);
        let url = converter.build_url(&exchange.request);
        assert_eq!(url, "http://127.0.0.1:8080/");
    }

    #[test]
    fn test_parse_cookies_from_headers() {
        let converter = Converter::new();
        let headers = vec![(
            "Cookie".to_string(),
            "session=abc123; user=john".to_string(),
        )];

        let cookies = converter.parse_cookies(&headers);
        assert_eq!(cookies.len(), 2);

        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, "abc123");
        assert_eq!(cookies[1].name, "user");
        assert_eq!(cookies[1].value, "john");
    }

    #[test]
    fn test_parse_set_cookies_with_attributes() {
        let converter = Converter::new();
        let headers = vec![(
            "Set-Cookie".to_string(),
            "session=xyz; Path=/; Domain=.example.com; HttpOnly; Secure".to_string(),
        )];

        let cookies = converter.parse_set_cookies(&headers);
        assert_eq!(cookies.len(), 1);

        let cookie = &cookies[0];
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "xyz");
        assert_eq!(cookie.path, Some("/".to_string()));
        assert_eq!(cookie.domain, Some(".example.com".to_string()));
        assert_eq!(cookie.http_only, Some(true));
        assert_eq!(cookie.secure, Some(true));
    }

    #[test]
    fn test_parse_query_string() {
        let converter = Converter::new();
        let url = "http://example.com/search?q=rust&lang=en&page=1";

        let params = converter.parse_query_string(url);
        assert_eq!(params.len(), 3);

        assert_eq!(params[0].name, "q");
        assert_eq!(params[0].value, "rust");
        assert_eq!(params[1].name, "lang");
        assert_eq!(params[1].value, "en");
        assert_eq!(params[2].name, "page");
        assert_eq!(params[2].value, "1");
    }

    #[test]
    fn test_parse_query_string_with_encoding() {
        let converter = Converter::new();
        let url = "http://example.com/search?q=hello%20world&special=%3D%26";

        let params = converter.parse_query_string(url);
        assert_eq!(params.len(), 2);

        assert_eq!(params[0].name, "q");
        assert_eq!(params[0].value, "hello world");
        assert_eq!(params[1].name, "special");
        assert_eq!(params[1].value, "=&");
    }

    #[test]
    fn test_parse_post_data_json() {
        let converter = Converter::new();
        let req = ParsedRequest {
            method: "POST".to_string(),
            path: "/api".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            )],
            body: br#"{"name":"test","value":123}"#.to_vec(),
            header_size: 0,
        };

        let req = normalized_request(req);
        let post_data = converter.parse_post_data(&req);
        assert!(post_data.is_some());

        let data = post_data.unwrap();
        assert_eq!(data.mime_type, "application/json");
        assert_eq!(data.text.unwrap(), r#"{"name":"test","value":123}"#);
        assert!(data.params.is_none());
    }

    #[test]
    fn test_parse_post_data_form_urlencoded() {
        let converter = Converter::new();
        let req = ParsedRequest {
            method: "POST".to_string(),
            path: "/submit".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: b"name=John&email=john%40example.com&age=30".to_vec(),
            header_size: 0,
        };

        let req = normalized_request(req);
        let post_data = converter.parse_post_data(&req);
        assert!(post_data.is_some());

        let data = post_data.unwrap();
        assert_eq!(data.mime_type, "application/x-www-form-urlencoded");
        assert!(data.params.is_some());

        let params = data.params.unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].value, Some("John".to_string()));
    }

    #[test]
    fn test_parse_post_data_empty_body() {
        let converter = Converter::new();
        let req = ParsedRequest {
            method: "POST".to_string(),
            path: "/api".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: vec![],
            header_size: 0,
        };

        let req = normalized_request(req);
        let post_data = converter.parse_post_data(&req);
        assert!(post_data.is_none());
    }

    #[test]
    fn test_build_response_with_content() {
        let converter = Converter::new();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "13".to_string()),
            ],
            body: br#"{"ok":true}"#.to_vec(),
            header_size: 0,
            encoded_body_size: 11,
            body_truncated: false,
        };

        let resp = normalized_response(resp);
        let response = converter.build_response(Some(&resp), "HTTP/1.1");
        assert_eq!(response.status, 200);
        assert_eq!(response.status_text, "OK");
        assert_eq!(response.content.mime_type, "application/json");
        assert_eq!(response.content.size, 11);
        assert!(response.content.text.is_some());
    }

    #[test]
    fn test_build_response_none() {
        let converter = Converter::new();
        let response = converter.build_response(None, "HTTP/1.1");

        assert_eq!(response.status, 0);
        assert_eq!(response.status_text, "");
        assert_eq!(response.content.size, 0);
        assert_eq!(response.headers_size, -1);
        assert_eq!(response.body_size, -1);
    }

    #[test]
    fn test_build_content_text() {
        let converter = Converter::new();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            body: b"<html><body>Hello</body></html>".to_vec(),
            header_size: 0,
            encoded_body_size: 31,
            body_truncated: false,
        };

        let resp = normalized_response(resp);
        let content = converter.build_content(&resp);
        assert_eq!(content.mime_type, "text/html");
        assert!(content.text.is_some());
        assert_eq!(content.encoding, None);
    }

    #[test]
    fn test_build_content_binary() {
        let converter = Converter::new();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Content-Type".to_string(), "image/png".to_string())],
            body: vec![0x89, 0x50, 0x4E, 0x47], // PNG header
            header_size: 0,
            encoded_body_size: 4,
            body_truncated: false,
        };

        let resp = normalized_response(resp);
        let content = converter.build_content(&resp);
        assert_eq!(content.mime_type, "image/png");
        assert!(content.text.is_some());
        assert_eq!(content.encoding, Some("base64".to_string()));
    }

    #[test]
    fn test_build_content_non_utf8_text_is_base64() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let converter = Converter::new();
        let body = b"<html>MZ\x90\x00\xff\xfe</html>".to_vec();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            body: body.clone(),
            header_size: 0,
            encoded_body_size: body.len(),
            body_truncated: false,
        };

        let resp = normalized_response(resp);
        let content = converter.build_content(&resp);
        assert_eq!(content.mime_type, "text/html");
        assert_eq!(content.encoding, Some("base64".to_string()));
        assert_eq!(STANDARD.decode(content.text.unwrap()).unwrap(), body);
    }

    #[test]
    fn test_is_text_content() {
        assert!(is_text_content("text/html"));
        assert!(is_text_content("text/plain"));
        assert!(is_text_content("application/json"));
        assert!(is_text_content("application/xml"));
        assert!(is_text_content("application/javascript"));

        assert!(!is_text_content("image/png"));
        assert!(!is_text_content("application/octet-stream"));
        assert!(!is_text_content("video/mp4"));
    }

    #[test]
    fn test_is_tls_data() {
        let tls_handshake = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        assert!(is_tls_data(&tls_handshake));

        let tls_app_data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        assert!(is_tls_data(&tls_app_data));

        let http_data = b"GET / HTTP/1.1\r\n";
        assert!(!is_tls_data(http_data));

        let short_data = vec![0x16, 0x03];
        assert!(!is_tls_data(&short_data));
    }

    #[test]
    fn test_conversation_to_entry() {
        let converter = Converter::new();
        let now = Utc::now();

        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/test".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![("Host".to_string(), "example.com".to_string())],
                body: vec![],
                header_size: 100,
            },
            response: Some(ParsedResponse {
                status: 200,
                reason: "OK".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 80,
                encoded_body_size: 0,
                body_truncated: false,
            }),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 80,
            request_timestamps: vec![now],
            response_timestamps: vec![now],
        };

        let exchange = normalize_conversation(conv, "http", None, 0);
        let entry = converter.exchange_to_entry(&exchange);
        assert_eq!(entry.request.method, "GET");
        assert_eq!(entry.response.status, 200);
        assert_eq!(entry.server_ip_address, Some("93.184.216.34".to_string()));
        assert_eq!(
            entry.connection.as_deref(),
            Some("192.168.1.10:54321->93.184.216.34:80")
        );

        let mut v6 = exchange.clone();
        v6.client = "[2001:db8::10]:54321".parse().unwrap();
        v6.server = "[2001:db8::20]:80".parse().unwrap();
        assert_eq!(
            converter.exchange_to_entry(&v6).connection.as_deref(),
            Some("[2001:db8::10]:54321->[2001:db8::20]:80")
        );
    }

    #[test]
    fn test_to_har_empty() {
        let converter = Converter::new();
        let har = converter.to_har();

        assert_eq!(har.log.version, "1.2");
        assert_eq!(har.log.creator.name, "pcap2har");
        assert!(har.log.entries.is_empty());
        assert!(har.log.pages.is_empty());
    }

    #[test]
    fn test_to_har_with_conversations() {
        let mut converter = Converter::new();
        let now = Utc::now();

        // Add a conversation
        converter.add_conversation(
            HttpConversation {
                request: ParsedRequest {
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![("Host".to_string(), "example.com".to_string())],
                    body: vec![],
                    header_size: 0,
                },
                response: Some(ParsedResponse {
                    status: 200,
                    reason: "OK".to_string(),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![],
                    body: vec![],
                    header_size: 0,
                    encoded_body_size: 0,
                    body_truncated: false,
                }),
                src_ip: "127.0.0.1".to_string(),
                dst_ip: "127.0.0.1".to_string(),
                src_port: 12345,
                dst_port: 80,
                request_timestamps: vec![now],
                response_timestamps: vec![now],
            },
            "http",
            None,
            0,
        );

        let har = converter.to_har();

        assert_eq!(har.log.entries.len(), 1);
        assert_eq!(har.log.pages.len(), 1);
        assert_eq!(har.log.entries[0].request.method, "GET");
        assert_eq!(har.log.entries[0].response.status, 200);
    }

    #[test]
    fn test_converter_sorts_conversations_by_time() {
        use chrono::Duration;

        let mut converter = Converter::new();
        let now = Utc::now();
        let earlier = now - Duration::seconds(10);
        let later = now + Duration::seconds(10);

        converter.add_conversation(
            HttpConversation {
                request: ParsedRequest {
                    method: "GET".to_string(),
                    path: "/second".to_string(),
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
            },
            "http",
            None,
            0,
        );

        converter.add_conversation(
            HttpConversation {
                request: ParsedRequest {
                    method: "GET".to_string(),
                    path: "/first".to_string(),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![],
                    body: vec![],
                    header_size: 0,
                },
                response: None,
                src_ip: "127.0.0.1".to_string(),
                dst_ip: "127.0.0.1".to_string(),
                src_port: 12346,
                dst_port: 80,
                request_timestamps: vec![earlier],
                response_timestamps: vec![],
            },
            "http",
            None,
            0,
        );

        converter.add_conversation(
            HttpConversation {
                request: ParsedRequest {
                    method: "GET".to_string(),
                    path: "/third".to_string(),
                    version: "HTTP/1.1".to_string(),
                    headers: vec![],
                    body: vec![],
                    header_size: 0,
                },
                response: None,
                src_ip: "127.0.0.1".to_string(),
                dst_ip: "127.0.0.1".to_string(),
                src_port: 12347,
                dst_port: 80,
                request_timestamps: vec![later],
                response_timestamps: vec![],
            },
            "http",
            None,
            0,
        );

        let har = converter.to_har();

        assert_eq!(har.log.entries[0].request.url, "http://127.0.0.1/first");
        assert_eq!(har.log.entries[1].request.url, "http://127.0.0.1/second");
        assert_eq!(har.log.entries[2].request.url, "http://127.0.0.1/third");
    }
}
