//! Connection-owned HPACK compression contexts and table-size update policy.
//!
//! Call [`HpackEncoderContext::set_allowed_maximum_size`] or
//! [`HpackDecoderContext::set_allowed_maximum_size`] when the corresponding HTTP/2
//! protocol maximum becomes effective. SETTINGS acknowledgement policy belongs to the
//! HTTP/2 connection owner, not this HPACK layer.

use super::decoder::{HpackBlockDecoder, HpackDecodeError};
use super::encoder::{HpackBlockEncoder, HpackEncodeError};
use super::table::HpackDynamicTable;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PendingSizes {
    minimum: Option<usize>,
    final_size: Option<usize>,
}

impl PendingSizes {
    pub(super) const fn next(self) -> Option<usize> {
        match self.minimum {
            Some(minimum) => Some(minimum),
            None => self.final_size,
        }
    }

    pub(super) fn advance(&mut self) {
        if self.minimum.is_some() {
            self.minimum = None;
        } else {
            self.final_size = None;
        }
    }

    fn queue_initial(&mut self, table_maximum: usize, allowed: usize) {
        if table_maximum > allowed {
            self.minimum = Some(allowed);
        }
    }

    fn record_change(&mut self, allowed: usize) {
        match self.minimum {
            None => {
                self.minimum = Some(allowed);
                self.final_size = None;
            }
            Some(minimum) if allowed <= minimum => {
                self.minimum = Some(allowed);
                self.final_size = None;
            }
            Some(minimum) => {
                self.minimum = Some(minimum);
                self.final_size = Some(allowed);
            }
        }
    }
}

/// Connection-owned HPACK encoder state for one HTTP/2 direction.
///
/// A successful [`HpackBlockEncoder::finish`] establishes completion of that block.
pub struct HpackEncoderContext<'storage, 'entries> {
    pub(super) table: HpackDynamicTable<'storage, 'entries>,
    allowed_maximum_size: usize,
    pub(super) pending: PendingSizes,
}

impl<'storage, 'entries> HpackEncoderContext<'storage, 'entries> {
    /// Creates an encoder context from caller-owned dynamic-table storage.
    pub fn new(
        table: HpackDynamicTable<'storage, 'entries>,
        allowed_maximum_size: usize,
    ) -> Result<Self, HpackEncodeError> {
        if allowed_maximum_size > table.capacity() {
            return Err(HpackEncodeError::AllowedMaximumExceedsCapacity {
                allowed: allowed_maximum_size,
                capacity: table.capacity(),
            });
        }
        let mut pending = PendingSizes::default();
        pending.queue_initial(table.maximum_size(), allowed_maximum_size);
        Ok(Self {
            table,
            allowed_maximum_size,
            pending,
        })
    }

    /// Returns the effective protocol maximum currently allowed for this direction.
    pub const fn allowed_maximum_size(&self) -> usize {
        self.allowed_maximum_size
    }

    /// Returns the dynamic table without permitting policy-desynchronizing mutation.
    pub const fn dynamic_table(&self) -> &HpackDynamicTable<'storage, 'entries> {
        &self.table
    }

    /// Returns the exact next required leading size update, if any.
    pub const fn next_required_size_update(&self) -> Option<usize> {
        self.pending.next()
    }

    /// Applies an effective HTTP/2 table-size policy change for this direction.
    pub fn set_allowed_maximum_size(&mut self, allowed: usize) -> Result<(), HpackEncodeError> {
        if allowed > self.table.capacity() {
            return Err(HpackEncodeError::AllowedMaximumExceedsCapacity {
                allowed,
                capacity: self.table.capacity(),
            });
        }
        if allowed != self.allowed_maximum_size {
            self.pending.record_change(allowed);
            self.allowed_maximum_size = allowed;
        }
        Ok(())
    }

    /// Begins one HPACK header block.
    pub fn begin_block(&mut self) -> HpackBlockEncoder<'_, 'storage, 'entries> {
        HpackBlockEncoder::from_context(
            &mut self.table,
            &mut self.pending,
            self.allowed_maximum_size,
        )
    }

    /// Recovers the caller-owned dynamic table.
    pub fn into_dynamic_table(self) -> HpackDynamicTable<'storage, 'entries> {
        self.table
    }
}

/// Connection-owned HPACK decoder state for one HTTP/2 direction.
pub struct HpackDecoderContext<'storage, 'entries> {
    pub(super) table: HpackDynamicTable<'storage, 'entries>,
    allowed_maximum_size: usize,
    pub(super) pending: PendingSizes,
}

impl<'storage, 'entries> HpackDecoderContext<'storage, 'entries> {
    /// Creates a decoder context from caller-owned dynamic-table storage.
    pub fn new(
        table: HpackDynamicTable<'storage, 'entries>,
        allowed_maximum_size: usize,
    ) -> Result<Self, HpackDecodeError> {
        if allowed_maximum_size > table.capacity() {
            return Err(HpackDecodeError::AllowedMaximumExceedsCapacity {
                allowed: allowed_maximum_size,
                capacity: table.capacity(),
            });
        }
        let mut pending = PendingSizes::default();
        pending.queue_initial(table.maximum_size(), allowed_maximum_size);
        Ok(Self {
            table,
            allowed_maximum_size,
            pending,
        })
    }

    /// Returns the effective protocol maximum currently allowed for this direction.
    pub const fn allowed_maximum_size(&self) -> usize {
        self.allowed_maximum_size
    }

    /// Returns the dynamic table without permitting policy-desynchronizing mutation.
    pub const fn dynamic_table(&self) -> &HpackDynamicTable<'storage, 'entries> {
        &self.table
    }

    /// Returns the exact next required leading size update, if any.
    pub const fn next_required_size_update(&self) -> Option<usize> {
        self.pending.next()
    }

    /// Applies an effective HTTP/2 table-size policy change for this direction.
    pub fn set_allowed_maximum_size(&mut self, allowed: usize) -> Result<(), HpackDecodeError> {
        if allowed > self.table.capacity() {
            return Err(HpackDecodeError::AllowedMaximumExceedsCapacity {
                allowed,
                capacity: self.table.capacity(),
            });
        }
        if allowed != self.allowed_maximum_size {
            self.pending.record_change(allowed);
            self.allowed_maximum_size = allowed;
        }
        Ok(())
    }

    /// Decodes one complete HPACK header block.
    pub fn decode_block<'block>(
        &mut self,
        block: &'block [u8],
    ) -> HpackBlockDecoder<'block, '_, 'storage, 'entries> {
        HpackBlockDecoder::from_context(
            block,
            &mut self.table,
            &mut self.pending,
            self.allowed_maximum_size,
        )
    }

    /// Recovers the caller-owned dynamic table.
    pub fn into_dynamic_table(self) -> HpackDynamicTable<'storage, 'entries> {
        self.table
    }
}
