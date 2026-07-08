use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::stream_io::stream_has_no_buffered_data;

pub(super) const EMPTY_EVICTION_SCAN_LIMIT: usize = 32;
const EMPTY_EVICTION_SCAN_PASSES: usize = 2;

#[derive(Debug)]
pub(super) struct TcpAdmission {
    cap: usize,
    state: Mutex<TcpAdmissionState>,
}

#[derive(Debug, Default)]
struct TcpAdmissionState {
    active: usize,
    next_id: u64,
    no_data: HashMap<u64, NoDataAdmission>,
    no_data_head: Option<u64>,
    no_data_tail: Option<u64>,
}

#[derive(Debug, Clone)]
struct NoDataAdmission {
    id: u64,
    cancel: CancellationToken,
    released: Arc<AtomicBool>,
    stream: Weak<TcpStream>,
    prev: Option<u64>,
    next: Option<u64>,
}

#[derive(Debug)]
pub(super) struct TcpAdmissionAttempt {
    pub(super) permit: Option<TcpAdmissionPermit>,
    pub(super) evicted_empty: bool,
}

#[derive(Debug)]
pub(super) struct TcpAdmissionPermit {
    id: u64,
    pub(super) cancel: CancellationToken,
    released: Arc<AtomicBool>,
    admission: Arc<TcpAdmission>,
}

impl TcpAdmission {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            cap,
            state: Mutex::new(TcpAdmissionState::default()),
        }
    }

    pub(super) fn admit_or_evict_empty(self: &Arc<Self>) -> TcpAdmissionAttempt {
        let mut evict_cancel = None;
        let mut evicted_empty = false;
        let mut permit = self.admit_if_under_cap();

        if permit.is_none() {
            for _ in 0..EMPTY_EVICTION_SCAN_PASSES {
                let mut removed_stale = false;

                for entry in self.eviction_candidates() {
                    if entry.is_empty() {
                        if let Some(cancel) = self.try_evict_empty(entry.id) {
                            evict_cancel = Some(cancel);
                            evicted_empty = true;
                            break;
                        }
                    } else {
                        self.remove_stale_no_data(entry.id);
                        removed_stale = true;
                    }
                }

                if evict_cancel.is_some() || !removed_stale {
                    break;
                }

                permit = self.admit_if_under_cap();
                if permit.is_some() {
                    break;
                }
            }

            if permit.is_none() {
                permit = self.admit_if_under_cap();
            }
        }

        if let Some(cancel) = evict_cancel {
            cancel.cancel();
        }

        TcpAdmissionAttempt {
            permit,
            evicted_empty,
        }
    }

    fn admit_if_under_cap(self: &Arc<Self>) -> Option<TcpAdmissionPermit> {
        let mut state = self.state.lock();
        if state.active < self.cap {
            Some(Self::admit_locked(self, &mut state))
        } else {
            None
        }
    }

    fn eviction_candidates(&self) -> Vec<NoDataAdmission> {
        let state = self.state.lock();
        if state.active < self.cap {
            return Vec::new();
        }

        let mut candidates = Vec::with_capacity(EMPTY_EVICTION_SCAN_LIMIT);
        let mut id = state.no_data_head;
        while candidates.len() < EMPTY_EVICTION_SCAN_LIMIT {
            let Some(current_id) = id else { break };
            let Some(entry) = state.no_data.get(&current_id) else {
                break;
            };
            id = entry.next;
            candidates.push(entry.clone());
        }
        drop(state);
        candidates
    }

    fn try_evict_empty(&self, id: u64) -> Option<CancellationToken> {
        let mut state = self.state.lock();
        if state.active < self.cap {
            return None;
        }

        let entry = Self::remove_no_data_locked(&mut state, id)?;
        if entry.released.swap(true, Ordering::AcqRel) {
            return None;
        }

        state.active = state.active.saturating_sub(1);
        drop(state);
        Some(entry.cancel)
    }

    fn remove_stale_no_data(&self, id: u64) {
        let mut state = self.state.lock();
        if Self::remove_no_data_locked(&mut state, id).is_some() {
            // The owner saw no data earlier but data is buffered now; it will
            // stay non-evictable unless a later classifier loop observes empty.
        }
    }

    fn insert_no_data_locked(state: &mut TcpAdmissionState, mut entry: NoDataAdmission) {
        let id = entry.id;
        entry.prev = state.no_data_tail;
        entry.next = None;

        if let Some(tail) = state.no_data_tail {
            if let Some(tail_entry) = state.no_data.get_mut(&tail) {
                tail_entry.next = Some(id);
            }
        } else {
            state.no_data_head = Some(id);
        }

        state.no_data_tail = Some(id);
        state.no_data.insert(id, entry);
    }

    fn remove_no_data_locked(state: &mut TcpAdmissionState, id: u64) -> Option<NoDataAdmission> {
        let entry = state.no_data.remove(&id)?;

        if let Some(prev) = entry.prev {
            if let Some(prev_entry) = state.no_data.get_mut(&prev) {
                prev_entry.next = entry.next;
            }
        } else {
            state.no_data_head = entry.next;
        }

        if let Some(next) = entry.next {
            if let Some(next_entry) = state.no_data.get_mut(&next) {
                next_entry.prev = entry.prev;
            }
        } else {
            state.no_data_tail = entry.prev;
        }

        Some(entry)
    }

    fn admit_locked(self: &Arc<Self>, state: &mut TcpAdmissionState) -> TcpAdmissionPermit {
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.active += 1;

        let cancel = CancellationToken::new();
        let released = Arc::new(AtomicBool::new(false));

        TcpAdmissionPermit {
            id,
            cancel,
            released,
            admission: self.clone(),
        }
    }
}

impl NoDataAdmission {
    fn is_empty(&self) -> bool {
        self.stream
            .upgrade()
            .is_some_and(|stream| stream_has_no_buffered_data(&stream))
    }
}

impl TcpAdmissionPermit {
    pub(super) fn is_released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }

    pub(super) fn mark_no_data_if_empty(&self, stream: &Arc<TcpStream>) -> bool {
        if !stream_has_no_buffered_data(stream) {
            return self.mark_data_seen();
        }

        let mut state = self.admission.state.lock();
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        if !state.no_data.contains_key(&self.id) {
            TcpAdmission::insert_no_data_locked(
                &mut state,
                NoDataAdmission {
                    id: self.id,
                    cancel: self.cancel.clone(),
                    released: self.released.clone(),
                    stream: Arc::downgrade(stream),
                    prev: None,
                    next: None,
                },
            );
        }
        drop(state);
        true
    }

    pub(super) fn mark_data_seen(&self) -> bool {
        let mut state = self.admission.state.lock();
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        TcpAdmission::remove_no_data_locked(&mut state, self.id);
        true
    }
}

impl Drop for TcpAdmissionPermit {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }

        let mut state = self.admission.state.lock();
        state.active = state.active.saturating_sub(1);
        TcpAdmission::remove_no_data_locked(&mut state, self.id);
        drop(state);
    }
}
