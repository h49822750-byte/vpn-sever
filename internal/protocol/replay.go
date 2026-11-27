package protocol

import (
	"sync"
	"sync/atomic"
)

// ReplayWindowSize is the width of the anti-replay sliding bitmap in packets.
const ReplayWindowSize = 128

// ReplayWindow implements a thread-safe 128-bit sliding window anti-replay filter
// with a lock-free atomic pre-check (Check) and mutex-serialized commit (Accept).
//
// Security invariant: callers MUST use Check(counter) prior to AEAD decryption to
// cheaply discard obvious replays without mutating state, and ONLY call Accept(counter)
// after AEAD authentication succeeds.
type ReplayWindow struct {
	// Lock-free atomic mirrors for zero-contention Check() and Highest() reads.
	highestAtomic atomic.Uint64
	hiAtomic      atomic.Uint64
	loAtomic      atomic.Uint64
	initAtomic    atomic.Bool

	mu          sync.Mutex
	highest     uint64
	hi          uint64 // bits 64..127 behind highest
	lo          uint64 // bits 0..63 behind highest (bit 0 == highest)
	initialized bool
}

// Check performs a lock-free optimistic check reporting whether counter is potentially valid
// (within or ahead of the sliding window and not yet marked as seen). It never mutates state.
func (rw *ReplayWindow) Check(counter uint64) bool {
	if !rw.initAtomic.Load() {
		return true
	}
	highest := rw.highestAtomic.Load()
	if counter > highest {
		return true
	}
	diff := highest - counter
	if diff >= ReplayWindowSize {
		return false
	}
	if diff < 64 {
		return ((rw.loAtomic.Load() >> diff) & 1) == 0
	}
	return ((rw.hiAtomic.Load() >> (diff - 64)) & 1) == 0
}

// Accept atomically checks whether counter is valid and marks it as seen, advancing
// the sliding window if counter > highest. Returns false if the counter is a replay
// or too old.
func (rw *ReplayWindow) Accept(counter uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if !rw.initialized {
		rw.initialized = true
		rw.highest = counter
		rw.lo = 1
		rw.hi = 0
		rw.publishLocked()
		return true
	}

	if counter > rw.highest {
		shift := counter - rw.highest
		if shift >= ReplayWindowSize {
			rw.hi = 0
			rw.lo = 1
		} else if shift >= 64 {
			rw.hi = rw.lo << (shift - 64)
			rw.lo = 1
		} else {
			rw.hi = (rw.hi << shift) | (rw.lo >> (64 - shift))
			rw.lo = (rw.lo << shift) | 1
		}
		rw.highest = counter
		rw.publishLocked()
		return true
	}

	diff := rw.highest - counter
	if diff >= ReplayWindowSize {
		return false
	}
	if diff < 64 {
		mask := uint64(1) << diff
		if (rw.lo & mask) != 0 {
			return false
		}
		rw.lo |= mask
		rw.loAtomic.Store(rw.lo)
		return true
	}
	mask := uint64(1) << (diff - 64)
	if (rw.hi & mask) != 0 {
		return false
	}
	rw.hi |= mask
	rw.hiAtomic.Store(rw.hi)
	return true
}

func (rw *ReplayWindow) publishLocked() {
	rw.loAtomic.Store(rw.lo)
	rw.hiAtomic.Store(rw.hi)
	rw.highestAtomic.Store(rw.highest)
	rw.initAtomic.Store(true)
}

// Highest returns the highest accepted packet sequence number so far without locking.
func (rw *ReplayWindow) Highest() uint64 {
	return rw.highestAtomic.Load()
}
