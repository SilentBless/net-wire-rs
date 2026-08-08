//! Caller-owned RFC 9204 dynamic-table storage.

use core::fmt;

use super::QpackHeaderFieldRef;

/// A caller-owned slot for a QPACK dynamic table entry.
///
/// Slots outside the table's current length are inactive. Their contents are not
/// cleared when entries are evicted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDynamicTableEntry {
    offset: usize,
    name_len: usize,
    value_len: usize,
}

impl QpackDynamicTableEntry {
    /// An inactive entry slot suitable for initializing caller-owned metadata.
    pub const EMPTY: Self = Self {
        offset: 0,
        name_len: 0,
        value_len: 0,
    };
}

/// A QPACK dynamic-table capacity, insertion, eviction, or index-resolution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDynamicTableError {
    /// The requested capacity exceeds the supplied storage's physical capacity.
    CapacityExceedsStorage {
        /// The requested RFC dynamic-table capacity.
        requested: usize,
        /// The greatest RFC dynamic-table capacity the supplied stores can support.
        capacity: usize,
    },
    /// The RFC entry-size calculation overflowed `usize`.
    EntrySizeOverflow,
    /// The entry cannot fit within the current dynamic-table capacity.
    EntryLargerThanCapacity {
        /// The calculated RFC entry size.
        entry_size: usize,
        /// The current RFC dynamic-table capacity.
        capacity: usize,
    },
    /// A successful insertion would overflow the absolute insert count.
    InsertCountOverflow,
    /// An eviction required by an operation was rejected by the caller's policy.
    EvictionBlocked {
        /// The zero-based absolute index of the first entry whose eviction was rejected.
        absolute_index: u64,
    },
    /// An encoder-relative index exceeded the current insert count.
    EncoderRelativeIndexUnderflow {
        /// The current insert count.
        insert_count: u64,
        /// The requested encoder-relative index.
        index: u64,
    },
    /// A field-relative index exceeded its base.
    FieldRelativeIndexUnderflow {
        /// The field section's base.
        base: u64,
        /// The requested field-relative index.
        index: u64,
    },
    /// A post-base index overflowed its base.
    PostBaseIndexOverflow {
        /// The field section's base.
        base: u64,
        /// The requested post-base index.
        index: u64,
    },
    /// An absolute index has not yet been inserted.
    FutureAbsoluteIndex {
        /// The requested zero-based absolute index.
        requested: u64,
        /// The current insert count.
        insert_count: u64,
    },
    /// An absolute index was evicted from the active table.
    EvictedAbsoluteIndex {
        /// The requested zero-based absolute index.
        requested: u64,
        /// The oldest zero-based absolute index still available.
        oldest_available: u64,
    },
    /// A field-line reference is at or after its Required Insert Count.
    ReferenceAtOrAfterRequiredInsertCount {
        /// The requested zero-based absolute index.
        requested: u64,
        /// The field section's Required Insert Count.
        required_insert_count: u64,
    },
}

impl fmt::Display for QpackDynamicTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceedsStorage {
                requested,
                capacity,
            } => {
                write!(
                    formatter,
                    "requested capacity {requested} exceeds storage capacity {capacity}"
                )
            }
            Self::EntrySizeOverflow => formatter.write_str("QPACK entry size overflowed usize"),
            Self::EntryLargerThanCapacity {
                entry_size,
                capacity,
            } => write!(
                formatter,
                "entry size {entry_size} exceeds capacity {capacity}"
            ),
            Self::InsertCountOverflow => formatter.write_str("QPACK insert count overflowed u64"),
            Self::EvictionBlocked { absolute_index } => {
                write!(
                    formatter,
                    "eviction of absolute index {absolute_index} was blocked"
                )
            }
            Self::EncoderRelativeIndexUnderflow {
                insert_count,
                index,
            } => write!(
                formatter,
                "encoder-relative index {index} exceeds insert count {insert_count}"
            ),
            Self::FieldRelativeIndexUnderflow { base, index } => {
                write!(
                    formatter,
                    "field-relative index {index} exceeds base {base}"
                )
            }
            Self::PostBaseIndexOverflow { base, index } => {
                write!(formatter, "post-base index {index} overflows base {base}")
            }
            Self::FutureAbsoluteIndex {
                requested,
                insert_count,
            } => write!(
                formatter,
                "absolute index {requested} is at or after insert count {insert_count}"
            ),
            Self::EvictedAbsoluteIndex {
                requested,
                oldest_available,
            } => write!(
                formatter,
                "absolute index {requested} was evicted; oldest available is {oldest_available}"
            ),
            Self::ReferenceAtOrAfterRequiredInsertCount {
                requested,
                required_insert_count,
            } => write!(
                formatter,
                "absolute index {requested} is at or after required insert count {required_insert_count}"
            ),
        }
    }
}

impl core::error::Error for QpackDynamicTableError {}

/// Caller-owned, allocation-free RFC 9204 dynamic-table storage.
///
/// Active entries and their bytes are packed newest first. Absolute indexes begin
/// at zero and are never reset by eviction or capacity changes.
pub struct QpackDynamicTable<'storage, 'entries> {
    storage: &'storage mut [u8],
    entries: &'entries mut [QpackDynamicTableEntry],
    len: usize,
    size: usize,
    capacity: usize,
    storage_capacity: usize,
    insert_count: u64,
}

impl<'storage, 'entries> QpackDynamicTable<'storage, 'entries> {
    /// Creates an empty table backed by caller-supplied byte and metadata storage.
    pub fn new(
        storage: &'storage mut [u8],
        entries: &'entries mut [QpackDynamicTableEntry],
    ) -> Self {
        let storage_capacity = Self::calculate_storage_capacity(storage.len(), entries.len());
        Self {
            storage,
            entries,
            len: 0,
            size: 0,
            capacity: 0,
            storage_capacity,
            insert_count: 0,
        }
    }

    /// Returns the greatest RFC dynamic-table capacity the supplied stores support.
    pub const fn storage_capacity(&self) -> usize {
        self.storage_capacity
    }

    /// Returns the current RFC dynamic-table capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current RFC dynamic-table size.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the number of active dynamic-table entries.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no dynamic-table entries are active.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of successful insertions since this table was created.
    pub const fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Returns the oldest active zero-based absolute index, if any.
    pub fn oldest_active_absolute(&self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        u64::try_from(self.len)
            .ok()
            .and_then(|len| self.insert_count.checked_sub(len))
    }

    /// Calculates an RFC 9204 entry size from opaque name and value bytes.
    pub fn entry_size(name: &[u8], value: &[u8]) -> Result<usize, QpackDynamicTableError> {
        name.len()
            .checked_add(value.len())
            .and_then(|length| length.checked_add(32))
            .ok_or(QpackDynamicTableError::EntrySizeOverflow)
    }

    /// Updates capacity, evicting the oldest entries allowed by `evictable` as needed.
    pub fn set_capacity<F>(
        &mut self,
        capacity: usize,
        mut evictable: F,
    ) -> Result<(), QpackDynamicTableError>
    where
        F: FnMut(u64) -> bool,
    {
        if capacity > self.storage_capacity {
            return Err(QpackDynamicTableError::CapacityExceedsStorage {
                requested: capacity,
                capacity: self.storage_capacity,
            });
        }

        let (retained_len, retained_size) = self.retained_for_capacity(capacity);
        self.confirm_evictions(retained_len, &mut evictable)?;
        self.len = retained_len;
        self.size = retained_size;
        self.capacity = capacity;
        Ok(())
    }

    /// Copies a field into the table as the newest entry and returns its absolute index.
    pub fn insert<F>(
        &mut self,
        name: &[u8],
        value: &[u8],
        mut evictable: F,
    ) -> Result<u64, QpackDynamicTableError>
    where
        F: FnMut(u64) -> bool,
    {
        let entry_size = Self::entry_size(name, value)?;
        if entry_size > self.capacity {
            return Err(QpackDynamicTableError::EntryLargerThanCapacity {
                entry_size,
                capacity: self.capacity,
            });
        }
        let target_size = self.capacity - entry_size;
        let (retained_len, retained_size) = self.retained_for_capacity(target_size);
        self.confirm_evictions(retained_len, &mut evictable)?;
        let next_insert_count = self
            .insert_count
            .checked_add(1)
            .ok_or(QpackDynamicTableError::InsertCountOverflow)?;

        let byte_len = name.len() + value.len();
        let retained_bytes = self.packed_bytes(retained_len);
        self.storage.copy_within(0..retained_bytes, byte_len);
        if retained_len > 0 {
            self.entries.copy_within(0..retained_len, 1);
            for entry in &mut self.entries[1..=retained_len] {
                entry.offset += byte_len;
            }
        }
        self.storage[..name.len()].copy_from_slice(name);
        self.storage[name.len()..byte_len].copy_from_slice(value);
        self.entries[0] = QpackDynamicTableEntry {
            offset: 0,
            name_len: name.len(),
            value_len: value.len(),
        };
        self.len = retained_len + 1;
        self.size = retained_size + entry_size;
        let absolute = self.insert_count;
        self.insert_count = next_insert_count;
        Ok(absolute)
    }

    /// Resolves a zero-based absolute index to an active borrowed header field.
    pub fn get_absolute(
        &self,
        absolute: u64,
    ) -> Result<QpackHeaderFieldRef<'_>, QpackDynamicTableError> {
        if absolute >= self.insert_count {
            return Err(QpackDynamicTableError::FutureAbsoluteIndex {
                requested: absolute,
                insert_count: self.insert_count,
            });
        }
        let oldest_available = match self.oldest_active_absolute() {
            Some(oldest) => oldest,
            None => self.insert_count,
        };
        if absolute < oldest_available {
            return Err(QpackDynamicTableError::EvictedAbsoluteIndex {
                requested: absolute,
                oldest_available,
            });
        }
        let slot = (self.insert_count - absolute - 1) as usize;
        let entry = self.entries[slot];
        let name_end = entry.offset + entry.name_len;
        let value_end = name_end + entry.value_len;
        Ok(QpackHeaderFieldRef::new(
            &self.storage[entry.offset..name_end],
            &self.storage[name_end..value_end],
        ))
    }

    /// Resolves an encoder-stream relative index to an active borrowed header field.
    pub fn get_encoder_relative(
        &self,
        relative: u64,
    ) -> Result<QpackHeaderFieldRef<'_>, QpackDynamicTableError> {
        let absolute = self
            .insert_count
            .checked_sub(relative)
            .and_then(|count| count.checked_sub(1))
            .ok_or(QpackDynamicTableError::EncoderRelativeIndexUnderflow {
                insert_count: self.insert_count,
                index: relative,
            })?;
        self.get_absolute(absolute)
    }

    /// Resolves a field-section relative index to an active borrowed header field.
    pub fn get_field_relative(
        &self,
        required_insert_count: u64,
        base: u64,
        relative: u64,
    ) -> Result<QpackHeaderFieldRef<'_>, QpackDynamicTableError> {
        let absolute = base
            .checked_sub(relative)
            .and_then(|base| base.checked_sub(1))
            .ok_or(QpackDynamicTableError::FieldRelativeIndexUnderflow {
                base,
                index: relative,
            })?;
        self.get_before_required_insert_count(absolute, required_insert_count)
    }

    /// Resolves a post-base index to an active borrowed header field.
    pub fn get_post_base(
        &self,
        required_insert_count: u64,
        base: u64,
        post_base: u64,
    ) -> Result<QpackHeaderFieldRef<'_>, QpackDynamicTableError> {
        let absolute =
            base.checked_add(post_base)
                .ok_or(QpackDynamicTableError::PostBaseIndexOverflow {
                    base,
                    index: post_base,
                })?;
        self.get_before_required_insert_count(absolute, required_insert_count)
    }

    fn get_before_required_insert_count(
        &self,
        absolute: u64,
        required_insert_count: u64,
    ) -> Result<QpackHeaderFieldRef<'_>, QpackDynamicTableError> {
        if absolute >= required_insert_count {
            return Err(
                QpackDynamicTableError::ReferenceAtOrAfterRequiredInsertCount {
                    requested: absolute,
                    required_insert_count,
                },
            );
        }
        self.get_absolute(absolute)
    }

    fn retained_for_capacity(&self, capacity: usize) -> (usize, usize) {
        let mut len = self.len;
        let mut size = self.size;
        while len > 0 && size > capacity {
            len -= 1;
            size -= Self::entry_size_from_slot(self.entries[len]);
        }
        (len, size)
    }

    fn confirm_evictions<F>(
        &self,
        retained_len: usize,
        evictable: &mut F,
    ) -> Result<(), QpackDynamicTableError>
    where
        F: FnMut(u64) -> bool,
    {
        for slot in (retained_len..self.len).rev() {
            let absolute_index = self.insert_count - slot as u64 - 1;
            if !evictable(absolute_index) {
                return Err(QpackDynamicTableError::EvictionBlocked { absolute_index });
            }
        }
        Ok(())
    }

    fn packed_bytes(&self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            let entry = self.entries[len - 1];
            entry.offset + entry.name_len + entry.value_len
        }
    }

    const fn calculate_storage_capacity(storage_len: usize, entry_capacity: usize) -> usize {
        let bytes = storage_len.saturating_add(32);
        let entries = entry_capacity.saturating_mul(32).saturating_add(31);
        if bytes < entries { bytes } else { entries }
    }

    const fn entry_size_from_slot(entry: QpackDynamicTableEntry) -> usize {
        entry.name_len + entry.value_len + 32
    }
}
