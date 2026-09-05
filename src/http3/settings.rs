use crate::DecodeLimits;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerSettings {
    pub qpack_max_table_capacity: usize,
    pub max_field_section_size: Option<u64>,
    pub qpack_blocked_streams: usize,
    pub enable_connect_protocol: bool,
    pub h3_datagram: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    #[error("duplicate HTTP/3 setting {0}")]
    Duplicate(u64),
    #[error("invalid boolean HTTP/3 setting {0}")]
    InvalidBoolean(u64),
}

impl PeerSettings {
    pub fn decode(values: &[(u64, u64)], limits: &DecodeLimits) -> Result<Self, SettingsError> {
        let mut settings = Self::default();
        let mut seen = BTreeSet::new();
        for &(identifier, value) in values {
            if !seen.insert(identifier) {
                return Err(SettingsError::Duplicate(identifier));
            }
            match identifier {
                0x01 => {
                    settings.qpack_max_table_capacity = usize::try_from(value)
                        .unwrap_or(usize::MAX)
                        .min(limits.max_qpack_table_bytes);
                }
                0x06 => {
                    settings.max_field_section_size =
                        Some(value.min(
                            u64::try_from(limits.max_header_section_bytes).unwrap_or(u64::MAX),
                        ));
                }
                0x07 => {
                    settings.qpack_blocked_streams = usize::try_from(value)
                        .unwrap_or(usize::MAX)
                        .min(limits.max_blocked_header_sections);
                }
                0x08 => settings.enable_connect_protocol = boolean(identifier, value)?,
                0x33 => settings.h3_datagram = boolean(identifier, value)?,
                _ => {}
            }
        }
        Ok(settings)
    }
}

fn boolean(identifier: u64, value: u64) -> Result<bool, SettingsError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SettingsError::InvalidBoolean(identifier)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_settings_and_clamps_allocating_values() {
        let limits = DecodeLimits::testing();
        assert!(matches!(
            PeerSettings::decode(&[(1, 2), (1, 3)], &limits),
            Err(SettingsError::Duplicate(1))
        ));
        let settings = PeerSettings::decode(&[(1, u64::MAX), (7, u64::MAX)], &limits).unwrap();
        assert_eq!(
            settings.qpack_max_table_capacity,
            limits.max_qpack_table_bytes
        );
        assert_eq!(
            settings.qpack_blocked_streams,
            limits.max_blocked_header_sections
        );
    }
}
