//! Caller-owned accounting for QPACK field sections awaiting insertions.

use core::fmt;
use core::iter::FusedIterator;

use crate::qpack::field::section::decode::QpackFieldSectionBlocked;

/// A caller-owned record of one stream with unresolved QPACK field sections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackBlockedStream {
    occupied: bool,
    stream_id: u64,
    required_insert_count: u64,
}

impl QpackBlockedStream {
    /// An unoccupied record suitable for caller-supplied blocked-stream storage.
    pub const EMPTY: Self = Self {
        occupied: false,
        stream_id: 0,
        required_insert_count: 0,
    };

    /// Returns the stream identifier for this record.
    pub const fn stream_id(self) -> u64 {
        self.stream_id
    }

    /// Returns the greatest unresolved Required Insert Count for this stream.
    pub const fn required_insert_count(self) -> u64 {
        self.required_insert_count
    }
}

/// A QPACK blocked-stream accounting failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackBlockedStreamsError {
    /// The advertised maximum cannot be represented by or does not fit supplied storage.
    MaximumBlockedStreamsExceedsStorage {
        /// The requested SETTINGS_QPACK_BLOCKED_STREAMS value.
        maximum: u64,
        /// The number of supplied record slots.
        storage_capacity: usize,
    },
    /// Registering another distinct stream exceeds the advertised maximum.
    BlockedStreamsLimitExceeded {
        /// The advertised SETTINGS_QPACK_BLOCKED_STREAMS value.
        maximum: u64,
    },
}

impl QpackBlockedStreamsError {
    /// Returns whether this error represents QPACK decompression failure.
    pub const fn is_decompression_failed(self) -> bool {
        matches!(self, Self::BlockedStreamsLimitExceeded { .. })
    }

    /// Returns whether this error is a caller storage provisioning mismatch.
    pub const fn is_provisioning_error(self) -> bool {
        matches!(self, Self::MaximumBlockedStreamsExceedsStorage { .. })
    }
}

impl fmt::Display for QpackBlockedStreamsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaximumBlockedStreamsExceedsStorage {
                maximum,
                storage_capacity,
            } => write!(
                formatter,
                "maximum blocked streams {maximum} exceeds storage capacity {storage_capacity}"
            ),
            Self::BlockedStreamsLimitExceeded { maximum } => {
                write!(formatter, "blocked streams exceed maximum {maximum}")
            }
        }
    }
}

impl core::error::Error for QpackBlockedStreamsError {}

/// Caller-owned accounting for streams with unresolved QPACK field sections.
///
/// `maximum_blocked_streams` is the local decoder's advertised
/// SETTINGS_QPACK_BLOCKED_STREAMS value. Registering the same stream aggregates the
/// greatest Required Insert Count across its started unresolved sections. Ready records
/// remain registered until explicitly removed. The caller and HTTP/3 own encoded bytes
/// and stream lifecycle; remove a record after a successful represented retry or when
/// its stream is abandoned or reset.
pub struct QpackBlockedStreams<'storage> {
    records: &'storage mut [QpackBlockedStream],
    maximum_blocked_streams: u64,
    len: usize,
}

impl<'storage> QpackBlockedStreams<'storage> {
    /// Creates empty accounting backed by caller-supplied records.
    ///
    /// On failure, the supplied records are unchanged. On success, every supplied
    /// record is initialized to [`QpackBlockedStream::EMPTY`].
    pub fn new(
        records: &'storage mut [QpackBlockedStream],
        maximum_blocked_streams: u64,
    ) -> Result<Self, QpackBlockedStreamsError> {
        let maximum = match usize::try_from(maximum_blocked_streams) {
            Ok(maximum) => maximum,
            Err(_) => {
                return Err(
                    QpackBlockedStreamsError::MaximumBlockedStreamsExceedsStorage {
                        maximum: maximum_blocked_streams,
                        storage_capacity: records.len(),
                    },
                );
            }
        };
        if maximum > records.len() {
            return Err(
                QpackBlockedStreamsError::MaximumBlockedStreamsExceedsStorage {
                    maximum: maximum_blocked_streams,
                    storage_capacity: records.len(),
                },
            );
        }
        for record in records.iter_mut() {
            *record = QpackBlockedStream::EMPTY;
        }
        Ok(Self {
            records,
            maximum_blocked_streams,
            len: 0,
        })
    }

    /// Returns the local decoder's advertised SETTINGS_QPACK_BLOCKED_STREAMS value.
    pub const fn maximum_blocked_streams(&self) -> u64 {
        self.maximum_blocked_streams
    }

    /// Returns the number of caller-supplied physical record slots.
    pub const fn storage_capacity(&self) -> usize {
        self.records.len()
    }

    /// Returns the number of distinct registered streams.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no streams are registered.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether a stream has a registered unresolved field section.
    pub fn contains(&self, stream_id: u64) -> bool {
        self.records
            .iter()
            .any(|record| record.occupied && record.stream_id == stream_id)
    }

    /// Returns whether a registered stream still awaits insertions at `insert_count`.
    pub fn is_blocked(&self, stream_id: u64, insert_count: u64) -> bool {
        self.records.iter().any(|record| {
            record.occupied
                && record.stream_id == stream_id
                && record.required_insert_count > insert_count
        })
    }

    /// Registers a blocked field section for a stream.
    ///
    /// Re-registering a stream preserves the greatest Required Insert Count across its
    /// started unresolved sections.
    pub fn register(
        &mut self,
        stream_id: u64,
        blocked: QpackFieldSectionBlocked,
    ) -> Result<(), QpackBlockedStreamsError> {
        for record in self.records.iter_mut() {
            if record.occupied && record.stream_id == stream_id {
                record.required_insert_count = record
                    .required_insert_count
                    .max(blocked.required_insert_count());
                return Ok(());
            }
        }
        if self.len >= self.maximum_blocked_streams as usize {
            return Err(QpackBlockedStreamsError::BlockedStreamsLimitExceeded {
                maximum: self.maximum_blocked_streams,
            });
        }
        for record in self.records.iter_mut() {
            if !record.occupied {
                *record = QpackBlockedStream {
                    occupied: true,
                    stream_id,
                    required_insert_count: blocked.required_insert_count(),
                };
                self.len += 1;
                return Ok(());
            }
        }
        Err(QpackBlockedStreamsError::BlockedStreamsLimitExceeded {
            maximum: self.maximum_blocked_streams,
        })
    }

    /// Removes a stream's accounting record, returning whether it was registered.
    pub fn remove(&mut self, stream_id: u64) -> bool {
        for record in self.records.iter_mut() {
            if record.occupied && record.stream_id == stream_id {
                *record = QpackBlockedStream::EMPTY;
                self.len -= 1;
                return true;
            }
        }
        false
    }

    /// Iterates registered records ready to retry at `insert_count`.
    pub fn ready(&self, insert_count: u64) -> QpackReadyBlockedStreamIter<'_> {
        QpackReadyBlockedStreamIter {
            remaining: self.records,
            insert_count,
        }
    }
}

/// An iterator over blocked streams whose Required Insert Count has been reached.
#[derive(Clone, Debug)]
pub struct QpackReadyBlockedStreamIter<'a> {
    remaining: &'a [QpackBlockedStream],
    insert_count: u64,
}

impl Iterator for QpackReadyBlockedStreamIter<'_> {
    type Item = QpackBlockedStream;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((record, remaining)) = self.remaining.split_first() {
            self.remaining = remaining;
            if record.occupied && record.required_insert_count <= self.insert_count {
                return Some(*record);
            }
        }
        None
    }
}

impl FusedIterator for QpackReadyBlockedStreamIter<'_> {}
