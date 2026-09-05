use crate::DecodeLimits;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct SharedBudget {
    inner: Arc<Mutex<BudgetState>>,
}

#[derive(Debug)]
struct BudgetState {
    used: usize,
    limit: usize,
}

impl SharedBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BudgetState { used: 0, limit })),
        }
    }

    pub fn used(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).used
    }

    fn reserve(&self, bytes: usize) -> Result<(), ReassemblyError> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let next = state
            .used
            .checked_add(bytes)
            .ok_or(ReassemblyError::ResourceLimit)?;
        if next > state.limit {
            return Err(ReassemblyError::ResourceLimit);
        }
        state.used = next;
        Ok(())
    }

    fn release(&self, bytes: usize) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.used = state.used.saturating_sub(bytes);
    }
}

#[derive(Debug, Clone)]
pub struct StreamLimits {
    pub max_ranges: usize,
    pub max_bytes: usize,
    pub shared: SharedBudget,
}

impl StreamLimits {
    pub fn from_decode_limits(limits: &DecodeLimits, shared: SharedBudget) -> Self {
        Self {
            max_ranges: limits.max_ranges_per_stream,
            max_bytes: limits.max_stream_bytes,
            shared,
        }
    }

    #[doc(hidden)]
    pub fn testing() -> Self {
        Self {
            max_ranges: 8,
            max_bytes: 1024,
            shared: SharedBudget::new(4096),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReassemblyError {
    #[error("fragment range overflows")]
    OffsetOverflow,
    #[error("overlapping fragment bytes conflict")]
    ConflictingOverlap,
    #[error("stream final size conflicts with observed data")]
    FinalSize,
    #[error("stream reassembly limit exceeded")]
    ResourceLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassemblySnapshot {
    next_offset: u64,
    final_size: Option<u64>,
    ranges: Vec<(u64, Vec<u8>)>,
    buffered_bytes: usize,
}

pub struct SparseReassembler {
    limits: StreamLimits,
    ranges: BTreeMap<u64, Vec<u8>>,
    next_offset: u64,
    final_size: Option<u64>,
    buffered_bytes: usize,
}

impl SparseReassembler {
    pub fn new(limits: StreamLimits) -> Self {
        Self {
            limits,
            ranges: BTreeMap::new(),
            next_offset: 0,
            final_size: None,
            buffered_bytes: 0,
        }
    }

    pub fn insert(
        &mut self,
        offset: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<Vec<u8>, ReassemblyError> {
        let length = u64::try_from(bytes.len()).map_err(|_| ReassemblyError::OffsetOverflow)?;
        let end = offset
            .checked_add(length)
            .ok_or(ReassemblyError::OffsetOverflow)?;
        self.validate_final_size(end, fin)?;

        let trim = self.next_offset.saturating_sub(offset).min(length);
        let start = offset + trim;
        let fragment =
            &bytes[usize::try_from(trim).map_err(|_| ReassemblyError::OffsetOverflow)?..];
        if !fragment.is_empty() {
            self.insert_buffered(start, fragment)?;
        }
        if fin {
            self.final_size = Some(end);
        }
        Ok(self.release_contiguous())
    }

    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn is_finished(&self) -> bool {
        self.final_size == Some(self.next_offset)
    }

    pub fn snapshot(&self) -> ReassemblySnapshot {
        ReassemblySnapshot {
            next_offset: self.next_offset,
            final_size: self.final_size,
            ranges: self
                .ranges
                .iter()
                .map(|(start, bytes)| (*start, bytes.clone()))
                .collect(),
            buffered_bytes: self.buffered_bytes,
        }
    }

    fn validate_final_size(&self, end: u64, fin: bool) -> Result<(), ReassemblyError> {
        if let Some(final_size) = self.final_size {
            if end > final_size || (fin && end != final_size) {
                return Err(ReassemblyError::FinalSize);
            }
        }
        if fin
            && (end < self.next_offset
                || self
                    .ranges
                    .iter()
                    .any(|(start, data)| start.saturating_add(data.len() as u64) > end))
        {
            return Err(ReassemblyError::FinalSize);
        }
        Ok(())
    }

    fn insert_buffered(&mut self, start: u64, fragment: &[u8]) -> Result<(), ReassemblyError> {
        let end = start
            .checked_add(fragment.len() as u64)
            .ok_or(ReassemblyError::OffsetOverflow)?;
        let mut selected = Vec::new();
        for (&range_start, data) in &self.ranges {
            let range_end = range_start + data.len() as u64;
            if range_end >= start && range_start <= end {
                validate_overlap(start, fragment, range_start, data)?;
                selected.push(range_start);
            }
        }

        let merged_start = selected
            .iter()
            .copied()
            .min()
            .map_or(start, |value| value.min(start));
        let merged_end = selected
            .iter()
            .filter_map(|key| self.ranges.get(key).map(|data| *key + data.len() as u64))
            .max()
            .map_or(end, |value| value.max(end));
        let merged_len = usize::try_from(merged_end - merged_start)
            .map_err(|_| ReassemblyError::ResourceLimit)?;
        let removed_bytes: usize = selected
            .iter()
            .filter_map(|key| self.ranges.get(key))
            .map(Vec::len)
            .sum();
        let added_bytes = merged_len.saturating_sub(removed_bytes);
        let next_buffered = self
            .buffered_bytes
            .checked_add(added_bytes)
            .ok_or(ReassemblyError::ResourceLimit)?;
        let next_ranges = self.ranges.len() + 1 - selected.len();
        if next_buffered > self.limits.max_bytes || next_ranges > self.limits.max_ranges {
            return Err(ReassemblyError::ResourceLimit);
        }

        let mut merged = vec![0; merged_len];
        for key in &selected {
            let data = &self.ranges[key];
            let at = usize::try_from(*key - merged_start).unwrap();
            merged[at..at + data.len()].copy_from_slice(data);
        }
        let at = usize::try_from(start - merged_start).unwrap();
        merged[at..at + fragment.len()].copy_from_slice(fragment);

        self.limits.shared.reserve(added_bytes)?;
        for key in selected {
            self.ranges.remove(&key);
        }
        self.ranges.insert(merged_start, merged);
        self.buffered_bytes = next_buffered;
        Ok(())
    }

    fn release_contiguous(&mut self) -> Vec<u8> {
        let mut output = Vec::new();
        while let Some(bytes) = self.ranges.remove(&self.next_offset) {
            self.next_offset = self.next_offset.saturating_add(bytes.len() as u64);
            self.buffered_bytes = self.buffered_bytes.saturating_sub(bytes.len());
            self.limits.shared.release(bytes.len());
            output.extend_from_slice(&bytes);
        }
        output
    }
}

impl Drop for SparseReassembler {
    fn drop(&mut self) {
        self.limits.shared.release(self.buffered_bytes);
    }
}

fn validate_overlap(
    first_start: u64,
    first: &[u8],
    second_start: u64,
    second: &[u8],
) -> Result<(), ReassemblyError> {
    let overlap_start = first_start.max(second_start);
    let overlap_end = (first_start + first.len() as u64).min(second_start + second.len() as u64);
    if overlap_start >= overlap_end {
        return Ok(());
    }
    let first_at = usize::try_from(overlap_start - first_start).unwrap();
    let second_at = usize::try_from(overlap_start - second_start).unwrap();
    let length = usize::try_from(overlap_end - overlap_start).unwrap();
    if first[first_at..first_at + length] != second[second_at..second_at + length] {
        return Err(ReassemblyError::ConflictingOverlap);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_out_of_order_data_once() {
        let mut reassembler = SparseReassembler::new(StreamLimits::testing());
        assert_eq!(reassembler.insert(5, b"world", false).unwrap(), b"");
        assert_eq!(
            reassembler.insert(0, b"hello", false).unwrap(),
            b"helloworld"
        );
        assert_eq!(reassembler.insert(0, b"helloworld", true).unwrap(), b"");
        assert!(reassembler.is_finished());
    }

    #[test]
    fn rejects_conflicting_overlap_without_changing_state() {
        let mut reassembler = SparseReassembler::new(StreamLimits::testing());
        reassembler.insert(3, b"def", false).unwrap();
        let before = reassembler.snapshot();
        assert_eq!(
            reassembler.insert(3, b"XYZ", false),
            Err(ReassemblyError::ConflictingOverlap)
        );
        assert_eq!(reassembler.snapshot(), before);
    }

    #[test]
    fn rejected_shared_budget_reservation_is_transactional() {
        let shared = SharedBudget::new(3);
        let limits = StreamLimits {
            max_ranges: 8,
            max_bytes: 8,
            shared: shared.clone(),
        };
        let mut reassembler = SparseReassembler::new(limits);
        let before = reassembler.snapshot();
        assert_eq!(
            reassembler.insert(4, b"four", false),
            Err(ReassemblyError::ResourceLimit)
        );
        assert_eq!(reassembler.snapshot(), before);
        assert_eq!(shared.used(), 0);
    }
}
