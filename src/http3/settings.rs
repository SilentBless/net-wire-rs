//! Semantic interpretation of validated HTTP/3 SETTINGS payloads.

use super::{Http3SettingId, Http3Settings, Http3SettingsSemanticError};

/// Validates SETTINGS semantics and returns the effective known peer settings.
pub(super) fn validate(
    settings: Http3Settings<'_>,
) -> Result<Http3PeerSettings, Http3SettingsSemanticError> {
    let mut peer_settings = Http3PeerSettings::default();
    let mut offset = 0;

    for (index, setting) in settings.settings().enumerate() {
        let id = setting.id();
        if prohibited_setting(id) {
            return Err(Http3SettingsSemanticError::ProhibitedSetting { id, offset });
        }
        for previous in settings.settings().take(index) {
            if previous.id() == id {
                return Err(Http3SettingsSemanticError::DuplicateSetting { id, offset });
            }
        }

        match id {
            Http3SettingId::QPACK_MAX_TABLE_CAPACITY => {
                peer_settings.qpack_max_table_capacity = setting.value();
            }
            Http3SettingId::MAX_FIELD_SECTION_SIZE => {
                peer_settings.maximum_field_section_size = Some(setting.value());
            }
            Http3SettingId::QPACK_BLOCKED_STREAMS => {
                peer_settings.qpack_blocked_streams = setting.value();
            }
            _ => {}
        }

        // Settings are disjoint subslices of one validated payload, so this cannot overflow.
        if let Some(next_offset) = offset.checked_add(setting.as_bytes().len()) {
            offset = next_offset;
        }
    }

    Ok(peer_settings)
}

/// Returns whether an identifier is reserved for HTTP/2 and prohibited in HTTP/3 SETTINGS.
pub(super) const fn prohibited_setting(id: Http3SettingId) -> bool {
    matches!(id.value(), 0x00 | 0x02 | 0x03 | 0x04 | 0x05)
}

/// Effective known SETTINGS received from an HTTP/3 peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Http3PeerSettings {
    qpack_max_table_capacity: u64,
    maximum_field_section_size: Option<u64>,
    qpack_blocked_streams: u64,
}

impl Http3PeerSettings {
    /// Returns SETTINGS_QPACK_MAX_TABLE_CAPACITY, defaulting to zero.
    pub const fn qpack_max_table_capacity(self) -> u64 {
        self.qpack_max_table_capacity
    }

    /// Returns SETTINGS_MAX_FIELD_SECTION_SIZE, or `None` for the unlimited default.
    pub const fn maximum_field_section_size(self) -> Option<u64> {
        self.maximum_field_section_size
    }

    /// Returns SETTINGS_QPACK_BLOCKED_STREAMS, defaulting to zero.
    pub const fn qpack_blocked_streams(self) -> u64 {
        self.qpack_blocked_streams
    }
}
