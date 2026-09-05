use super::crypto::QuicCipherSuite;

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const ALPN_EXTENSION: u16 = 0x0010;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsHandshakeMetadata {
    pub client_random: Option<[u8; 32]>,
    pub cipher_suite: Option<QuicCipherSuite>,
    pub offered_alpns: Vec<Vec<u8>>,
    pub selected_alpn: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsMetadataError {
    #[error("TLS handshake metadata exceeds configured limits")]
    LimitExceeded,
    #[error("malformed TLS handshake message")]
    Malformed,
    #[error("unsupported TLS cipher suite 0x{0:04x}")]
    UnsupportedCipher(u16),
}

pub struct TlsHandshakeParser {
    buffer: Vec<u8>,
    max_bytes: usize,
    metadata: TlsHandshakeMetadata,
}

impl TlsHandshakeParser {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_bytes,
            metadata: TlsHandshakeMetadata::default(),
        }
    }

    pub fn ingest(&mut self, data: &[u8]) -> Result<(), TlsMetadataError> {
        let next_len = self
            .buffer
            .len()
            .checked_add(data.len())
            .ok_or(TlsMetadataError::LimitExceeded)?;
        if next_len > self.max_bytes {
            return Err(TlsMetadataError::LimitExceeded);
        }
        self.buffer.extend_from_slice(data);

        let mut consumed = 0usize;
        while self.buffer.len().saturating_sub(consumed) >= 4 {
            let header = &self.buffer[consumed..consumed + 4];
            let body_len = (usize::from(header[1]) << 16)
                | (usize::from(header[2]) << 8)
                | usize::from(header[3]);
            if body_len > self.max_bytes {
                return Err(TlsMetadataError::LimitExceeded);
            }
            let message_len = 4usize
                .checked_add(body_len)
                .ok_or(TlsMetadataError::LimitExceeded)?;
            if self.buffer.len() - consumed < message_len {
                break;
            }
            let message_type = header[0];
            let body = &self.buffer[consumed + 4..consumed + message_len];
            match message_type {
                CLIENT_HELLO => parse_client_hello(body, &mut self.metadata)?,
                SERVER_HELLO => parse_server_hello(body, &mut self.metadata)?,
                ENCRYPTED_EXTENSIONS => parse_encrypted_extensions(body, &mut self.metadata)?,
                _ => {}
            }
            consumed += message_len;
        }
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        Ok(())
    }

    pub fn metadata(&self) -> &TlsHandshakeMetadata {
        &self.metadata
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
}

fn parse_client_hello(
    body: &[u8],
    metadata: &mut TlsHandshakeMetadata,
) -> Result<(), TlsMetadataError> {
    let mut cursor = Cursor::new(body);
    cursor.take(2)?;
    metadata.client_random = Some(
        cursor
            .take(32)?
            .try_into()
            .map_err(|_| TlsMetadataError::Malformed)?,
    );
    cursor.skip_u8_vector()?;
    cursor.skip_u16_vector()?;
    cursor.skip_u8_vector()?;
    if cursor.remaining() == 0 {
        return Ok(());
    }
    let extensions = cursor.u16_vector()?;
    metadata.offered_alpns = parse_alpn_extension(extensions)?.unwrap_or_default();
    Ok(())
}

fn parse_server_hello(
    body: &[u8],
    metadata: &mut TlsHandshakeMetadata,
) -> Result<(), TlsMetadataError> {
    let mut cursor = Cursor::new(body);
    cursor.take(2)?;
    cursor.take(32)?;
    cursor.skip_u8_vector()?;
    let suite = cursor.u16()?;
    metadata.cipher_suite = Some(match suite {
        0x1301 => QuicCipherSuite::Aes128GcmSha256,
        0x1302 => QuicCipherSuite::Aes256GcmSha384,
        0x1303 => QuicCipherSuite::ChaCha20Poly1305Sha256,
        value => return Err(TlsMetadataError::UnsupportedCipher(value)),
    });
    cursor.take(1)?;
    if cursor.remaining() > 0 {
        let _ = cursor.u16_vector()?;
    }
    Ok(())
}

fn parse_encrypted_extensions(
    body: &[u8],
    metadata: &mut TlsHandshakeMetadata,
) -> Result<(), TlsMetadataError> {
    let mut cursor = Cursor::new(body);
    let extensions = cursor.u16_vector()?;
    if let Some(protocols) = parse_alpn_extension(extensions)? {
        if protocols.len() != 1 {
            return Err(TlsMetadataError::Malformed);
        }
        metadata.selected_alpn = protocols.into_iter().next();
    }
    Ok(())
}

fn parse_alpn_extension(extensions: &[u8]) -> Result<Option<Vec<Vec<u8>>>, TlsMetadataError> {
    let mut cursor = Cursor::new(extensions);
    while cursor.remaining() > 0 {
        let extension_type = cursor.u16()?;
        let data = cursor.u16_vector()?;
        if extension_type != ALPN_EXTENSION {
            continue;
        }
        let mut alpn = Cursor::new(data).u16_vector_cursor()?;
        let mut protocols = Vec::new();
        while alpn.remaining() > 0 {
            let protocol = alpn.u8_vector()?;
            if protocol.is_empty() {
                return Err(TlsMetadataError::Malformed);
            }
            protocols.push(protocol.to_vec());
        }
        return Ok(Some(protocols));
    }
    Ok(None)
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TlsMetadataError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(TlsMetadataError::Malformed)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(TlsMetadataError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, TlsMetadataError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| TlsMetadataError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u8_vector(&mut self) -> Result<&'a [u8], TlsMetadataError> {
        let length = usize::from(*self.take(1)?.first().unwrap());
        self.take(length)
    }

    fn u16_vector(&mut self) -> Result<&'a [u8], TlsMetadataError> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn u16_vector_cursor(&mut self) -> Result<Cursor<'a>, TlsMetadataError> {
        Ok(Cursor::new(self.u16_vector()?))
    }

    fn skip_u8_vector(&mut self) -> Result<(), TlsMetadataError> {
        self.u8_vector().map(|_| ())
    }

    fn skip_u16_vector(&mut self) -> Result<(), TlsMetadataError> {
        self.u16_vector().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut output = vec![kind, 0, 0, u8::try_from(body.len()).unwrap()];
        output.extend_from_slice(body);
        output
    }

    #[test]
    fn parses_fragmented_client_and_server_metadata() {
        let mut client = vec![0x03, 0x03];
        client.extend_from_slice(&[0x11; 32]);
        client.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        client.extend_from_slice(&[0, 9, 0, 0x10, 0, 5, 0, 3, 2, b'h', b'3']);

        let mut server = vec![0x03, 0x03];
        server.extend_from_slice(&[0x22; 32]);
        server.extend_from_slice(&[0, 0x13, 0x03, 0, 0, 0]);

        let encrypted_extensions = [0, 9, 0, 0x10, 0, 5, 0, 3, 2, b'h', b'3'];
        let messages = [
            handshake(CLIENT_HELLO, &client),
            handshake(SERVER_HELLO, &server),
            handshake(ENCRYPTED_EXTENSIONS, &encrypted_extensions),
        ]
        .concat();
        let mut parser = TlsHandshakeParser::new(4096);
        for fragment in messages.chunks(7) {
            parser.ingest(fragment).unwrap();
        }
        let metadata = parser.metadata();
        assert_eq!(metadata.client_random, Some([0x11; 32]));
        assert_eq!(
            metadata.cipher_suite,
            Some(QuicCipherSuite::ChaCha20Poly1305Sha256)
        );
        assert_eq!(metadata.offered_alpns, vec![b"h3".to_vec()]);
        assert_eq!(metadata.selected_alpn.as_deref(), Some(&b"h3"[..]));
    }

    #[test]
    fn unknown_cipher_suite_is_typed() {
        let mut server = vec![0x03, 0x03];
        server.extend_from_slice(&[0x22; 32]);
        server.extend_from_slice(&[0, 0xde, 0xad, 0, 0, 0]);
        let mut parser = TlsHandshakeParser::new(4096);
        assert_eq!(
            parser.ingest(&handshake(SERVER_HELLO, &server)),
            Err(TlsMetadataError::UnsupportedCipher(0xdead))
        );
    }
}
