//! RFC 7541 Appendix A static header table.

/// A borrowed HPACK header field with byte-oriented name and value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackHeaderFieldRef<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> HpackHeaderFieldRef<'a> {
    /// Creates a borrowed header field from opaque name and value bytes.
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Returns the opaque header name bytes.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the opaque header value bytes.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// Number of entries in the RFC 7541 Appendix A static table.
pub const HPACK_STATIC_TABLE_LEN: usize = 61;

/// RFC 7541 Appendix A's immutable, one-based static header table.
pub struct HpackStaticTable;

impl HpackStaticTable {
    /// Returns the number of entries in the static table.
    pub const fn len() -> usize {
        HPACK_STATIC_TABLE_LEN
    }

    /// Returns whether the static table has no entries.
    pub const fn is_empty() -> bool {
        false
    }

    /// Returns the field at a one-based RFC 7541 Appendix A index.
    pub fn get(index: usize) -> Option<HpackHeaderFieldRef<'static>> {
        STATIC_TABLE.get(index.checked_sub(1)?).copied()
    }
}

const STATIC_TABLE: [HpackHeaderFieldRef<'static>; HPACK_STATIC_TABLE_LEN] = [
    HpackHeaderFieldRef::new(b":authority", b""),
    HpackHeaderFieldRef::new(b":method", b"GET"),
    HpackHeaderFieldRef::new(b":method", b"POST"),
    HpackHeaderFieldRef::new(b":path", b"/"),
    HpackHeaderFieldRef::new(b":path", b"/index.html"),
    HpackHeaderFieldRef::new(b":scheme", b"http"),
    HpackHeaderFieldRef::new(b":scheme", b"https"),
    HpackHeaderFieldRef::new(b":status", b"200"),
    HpackHeaderFieldRef::new(b":status", b"204"),
    HpackHeaderFieldRef::new(b":status", b"206"),
    HpackHeaderFieldRef::new(b":status", b"304"),
    HpackHeaderFieldRef::new(b":status", b"400"),
    HpackHeaderFieldRef::new(b":status", b"404"),
    HpackHeaderFieldRef::new(b":status", b"500"),
    HpackHeaderFieldRef::new(b"accept-charset", b""),
    HpackHeaderFieldRef::new(b"accept-encoding", b"gzip, deflate"),
    HpackHeaderFieldRef::new(b"accept-language", b""),
    HpackHeaderFieldRef::new(b"accept-ranges", b""),
    HpackHeaderFieldRef::new(b"accept", b""),
    HpackHeaderFieldRef::new(b"access-control-allow-origin", b""),
    HpackHeaderFieldRef::new(b"age", b""),
    HpackHeaderFieldRef::new(b"allow", b""),
    HpackHeaderFieldRef::new(b"authorization", b""),
    HpackHeaderFieldRef::new(b"cache-control", b""),
    HpackHeaderFieldRef::new(b"content-disposition", b""),
    HpackHeaderFieldRef::new(b"content-encoding", b""),
    HpackHeaderFieldRef::new(b"content-language", b""),
    HpackHeaderFieldRef::new(b"content-length", b""),
    HpackHeaderFieldRef::new(b"content-location", b""),
    HpackHeaderFieldRef::new(b"content-range", b""),
    HpackHeaderFieldRef::new(b"content-type", b""),
    HpackHeaderFieldRef::new(b"cookie", b""),
    HpackHeaderFieldRef::new(b"date", b""),
    HpackHeaderFieldRef::new(b"etag", b""),
    HpackHeaderFieldRef::new(b"expect", b""),
    HpackHeaderFieldRef::new(b"expires", b""),
    HpackHeaderFieldRef::new(b"from", b""),
    HpackHeaderFieldRef::new(b"host", b""),
    HpackHeaderFieldRef::new(b"if-match", b""),
    HpackHeaderFieldRef::new(b"if-modified-since", b""),
    HpackHeaderFieldRef::new(b"if-none-match", b""),
    HpackHeaderFieldRef::new(b"if-range", b""),
    HpackHeaderFieldRef::new(b"if-unmodified-since", b""),
    HpackHeaderFieldRef::new(b"last-modified", b""),
    HpackHeaderFieldRef::new(b"link", b""),
    HpackHeaderFieldRef::new(b"location", b""),
    HpackHeaderFieldRef::new(b"max-forwards", b""),
    HpackHeaderFieldRef::new(b"proxy-authenticate", b""),
    HpackHeaderFieldRef::new(b"proxy-authorization", b""),
    HpackHeaderFieldRef::new(b"range", b""),
    HpackHeaderFieldRef::new(b"referer", b""),
    HpackHeaderFieldRef::new(b"refresh", b""),
    HpackHeaderFieldRef::new(b"retry-after", b""),
    HpackHeaderFieldRef::new(b"server", b""),
    HpackHeaderFieldRef::new(b"set-cookie", b""),
    HpackHeaderFieldRef::new(b"strict-transport-security", b""),
    HpackHeaderFieldRef::new(b"transfer-encoding", b""),
    HpackHeaderFieldRef::new(b"user-agent", b""),
    HpackHeaderFieldRef::new(b"vary", b""),
    HpackHeaderFieldRef::new(b"via", b""),
    HpackHeaderFieldRef::new(b"www-authenticate", b""),
];

/// A caller-owned slot for an HPACK dynamic table entry.
///
/// Slots outside the table's current length are inactive. Their contents are not
/// cleared when entries are evicted or the table is cleared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackDynamicTableEntry {
    offset: usize,
    name_len: usize,
    value_len: usize,
}

impl HpackDynamicTableEntry {
    /// An inactive entry slot suitable for initializing caller-owned metadata.
    pub const EMPTY: Self = Self {
        offset: 0,
        name_len: 0,
        value_len: 0,
    };
}

/// An HPACK dynamic-table configuration or entry-size failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackDynamicTableError {
    /// The requested maximum size exceeds the supplied storage's physical capacity.
    MaximumSizeExceedsCapacity {
        /// The requested RFC dynamic-table size.
        requested: usize,
        /// The greatest RFC dynamic-table size the supplied stores can support.
        capacity: usize,
    },
    /// The RFC entry-size calculation overflowed `usize`.
    EntrySizeOverflow,
}

/// The result of inserting a header field into an HPACK dynamic table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackDynamicTableInsertResult {
    /// The field was copied into the table as its newest entry.
    Inserted,
    /// The field exceeded the current maximum, so the table was cleared without insertion.
    NotInsertedOversized,
}

/// Caller-owned, allocation-free RFC 7541 dynamic-table storage.
///
/// Entries are addressed with one-based dynamic indices, where index 1 is the
/// newest entry. The table stores only its active packed bytes and active metadata;
/// stale caller storage is never exposed after eviction or [`Self::clear`]. This
/// type intentionally does not combine dynamic indices with the static table.
pub struct HpackDynamicTable<'storage, 'entries> {
    storage: &'storage mut [u8],
    entries: &'entries mut [HpackDynamicTableEntry],
    count: usize,
    size: usize,
    maximum_size: usize,
    capacity: usize,
}

impl<'storage, 'entries> HpackDynamicTable<'storage, 'entries> {
    /// Creates a table backed by caller-supplied byte and metadata storage.
    ///
    /// The maximum is validated before either store is changed.
    pub fn new(
        storage: &'storage mut [u8],
        entries: &'entries mut [HpackDynamicTableEntry],
        maximum_size: usize,
    ) -> Result<Self, HpackDynamicTableError> {
        let capacity = Self::storage_capacity(storage.len(), entries.len());
        if maximum_size > capacity {
            return Err(HpackDynamicTableError::MaximumSizeExceedsCapacity {
                requested: maximum_size,
                capacity,
            });
        }
        Ok(Self {
            storage,
            entries,
            count: 0,
            size: 0,
            maximum_size,
            capacity,
        })
    }

    /// Returns the maximum RFC size supported by the supplied caller storage.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of active dynamic entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns whether no dynamic entries are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the current RFC dynamic-table size.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the current configured RFC dynamic-table maximum.
    pub const fn maximum_size(&self) -> usize {
        self.maximum_size
    }

    /// Returns the field at a one-based dynamic index, where 1 is newest.
    pub fn get(&self, index: usize) -> Option<HpackHeaderFieldRef<'_>> {
        let slot = index.checked_sub(1)?;
        if slot >= self.count {
            return None;
        }
        let entry = self.entries.get(slot)?;
        let name_end = entry.offset.checked_add(entry.name_len)?;
        let value_end = name_end.checked_add(entry.value_len)?;
        Some(HpackHeaderFieldRef::new(
            self.storage.get(entry.offset..name_end)?,
            self.storage.get(name_end..value_end)?,
        ))
    }

    /// Removes all active entries without scrubbing inactive caller storage.
    pub fn clear(&mut self) {
        self.count = 0;
        self.size = 0;
    }

    /// Updates the configured maximum, evicting oldest entries immediately if needed.
    pub fn set_maximum_size(&mut self, maximum_size: usize) -> Result<(), HpackDynamicTableError> {
        if maximum_size > self.capacity {
            return Err(HpackDynamicTableError::MaximumSizeExceedsCapacity {
                requested: maximum_size,
                capacity: self.capacity,
            });
        }
        self.set_maximum_size_prevalidated(maximum_size);
        Ok(())
    }

    /// Updates the maximum after the caller established `maximum_size <= self.capacity`.
    pub(super) fn set_maximum_size_prevalidated(&mut self, maximum_size: usize) {
        let mut count = self.count;
        let mut size = self.size;
        while count > 0 && size > maximum_size {
            count -= 1;
            size -= Self::entry_size_from_slot(self.entries[count]);
        }
        self.count = count;
        self.size = size;
        self.maximum_size = maximum_size;
    }

    /// Calculates an RFC 7541 entry size from opaque name and value bytes.
    pub fn entry_size(name: &[u8], value: &[u8]) -> Result<usize, HpackDynamicTableError> {
        name.len()
            .checked_add(value.len())
            .and_then(|length| length.checked_add(32))
            .ok_or(HpackDynamicTableError::EntrySizeOverflow)
    }

    /// Copies a field into the table as the newest entry, evicting oldest entries as needed.
    pub fn insert(
        &mut self,
        name: &[u8],
        value: &[u8],
    ) -> Result<HpackDynamicTableInsertResult, HpackDynamicTableError> {
        let entry_size = Self::entry_size(name, value)?;
        Ok(self.insert_prevalidated(name, value, entry_size))
    }

    /// Inserts a field whose RFC entry size was already calculated by [`Self::entry_size`].
    ///
    /// This HPACK-module path is infallible so callers can preflight before externally visible
    /// writes; `entry_size - 32` is the checked name-plus-value length established by that call.
    pub(super) fn insert_prevalidated(
        &mut self,
        name: &[u8],
        value: &[u8],
        entry_size: usize,
    ) -> HpackDynamicTableInsertResult {
        if entry_size > self.maximum_size {
            self.clear();
            return HpackDynamicTableInsertResult::NotInsertedOversized;
        }

        let byte_len = entry_size - 32;
        let mut retained_count = self.count;
        let mut retained_size = self.size;
        while retained_count > 0 && retained_size > self.maximum_size - entry_size {
            retained_count -= 1;
            retained_size -= Self::entry_size_from_slot(self.entries[retained_count]);
        }
        let retained_bytes = if retained_count == 0 {
            0
        } else {
            let last = self.entries[retained_count - 1];
            last.offset + last.name_len + last.value_len
        };

        // Validation above plus the constructor capacity proof guarantees these ranges fit.
        self.storage.copy_within(0..retained_bytes, byte_len);
        if retained_count > 0 {
            self.entries.copy_within(0..retained_count, 1);
            for entry in &mut self.entries[1..=retained_count] {
                entry.offset += byte_len;
            }
        }
        self.storage[..name.len()].copy_from_slice(name);
        self.storage[name.len()..byte_len].copy_from_slice(value);
        self.entries[0] = HpackDynamicTableEntry {
            offset: 0,
            name_len: name.len(),
            value_len: value.len(),
        };
        self.count = retained_count + 1;
        self.size = retained_size + entry_size;
        HpackDynamicTableInsertResult::Inserted
    }

    const fn storage_capacity(storage_len: usize, entry_capacity: usize) -> usize {
        let bytes = storage_len.saturating_add(32);
        let entries = entry_capacity.saturating_mul(32).saturating_add(31);
        if bytes < entries { bytes } else { entries }
    }

    const fn entry_size_from_slot(entry: HpackDynamicTableEntry) -> usize {
        entry.name_len + entry.value_len + 32
    }
}
