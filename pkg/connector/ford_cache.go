// Ford key cache — reimplementation of the 94f7b8e Ford cross-batch
// deduplication fix in Go, so the refactor branch can consume upstream
// OpenBubbles/rustpush unchanged. See _todo/20260304-attachment-fix.md
// for the original analysis and protocol details.
//
// Background:
//   - CloudKit iMessage videos are Ford-encrypted. Every CloudAttachment
//     record carries its own 32-byte Ford key in `lqa.protection_info`.
//   - MMCS deduplicates identical content at the storage layer, so when
//     the same video is sent multiple times, MMCS serves ONE encrypted
//     blob (encrypted with the original uploader's Ford key) for many
//     CloudAttachment records. The non-original records' own Ford keys
//     cannot decrypt the served blob.
//   - The fix: every Ford key seen during attachment sync is registered
//     in a global cache keyed by `fordChecksum = 0x01 || SHA1(key)`.
//     Before a download, the caller computes the record's checksum and
//     consults the cache. If a different key is cached for the same
//     chunk's checksum (discovered via the MMCS response), we pass the
//     cached key to the download wrapper so `get_mmcs` decrypts with
//     the original uploader's key.
//
// The cache is process-local and populated aggressively during sync.
// Nothing is persisted — if the bridge restarts, cache is rebuilt on
// the next sync cycle.

package connector

import (
	"crypto/sha1"
	"encoding/hex"
	"sync"

	"github.com/rs/zerolog/log"
)

// FordKeyCache stores Ford keys keyed by their `fordChecksum`
// (`0x01 || SHA1(key)`). Safe for concurrent Register/Lookup from
// multiple goroutines.
type FordKeyCache struct {
	mu    sync.RWMutex
	store map[string][]byte // hex(fordChecksum) → 32-byte Ford key
}

// NewFordKeyCache returns an empty, ready-to-use cache.
func NewFordKeyCache() *FordKeyCache {
	return &FordKeyCache{store: make(map[string][]byte)}
}

// Register caches a Ford key under its fordChecksum. No-op for
// zero-length input (some records may not carry a Ford key — e.g.
// image attachments that use V1 per-chunk encryption).
func (c *FordKeyCache) Register(fordKey []byte) {
	if len(fordKey) == 0 {
		return
	}
	checksum := FordChecksumOf(fordKey)
	key := hex.EncodeToString(checksum)
	c.mu.Lock()
	if _, exists := c.store[key]; exists {
		c.mu.Unlock()
		return
	}
	// Copy the slice so a later mutation by the caller can't
	// corrupt the cached value.
	stored := make([]byte, len(fordKey))
	copy(stored, fordKey)
	c.store[key] = stored
	size := len(c.store)
	c.mu.Unlock()
	// Mirror the `register_ford_key` log line from the original Rust
	// fix so operators can grep logs for cache population.
	log.Debug().
		Str("ford_checksum", hex.EncodeToString(checksum)).
		Int("cache_size", size).
		Msg("register_ford_key: cached Ford key for dedup fallback")
}

// Lookup returns the Ford key cached under the given fordChecksum,
// or nil + false if none is cached. Returned slices must not be
// mutated by the caller.
func (c *FordKeyCache) Lookup(fordChecksum []byte) ([]byte, bool) {
	if len(fordChecksum) == 0 {
		return nil, false
	}
	keyHex := hex.EncodeToString(fordChecksum)
	c.mu.RLock()
	v, ok := c.store[keyHex]
	size := len(c.store)
	c.mu.RUnlock()
	if ok {
		// Matches the "Ford SIV succeeded with cached key (dedup
		// resolved)" log intent from the original Rust fix.
		log.Info().
			Str("ford_checksum", keyHex).
			Int("cache_size", size).
			Msg("Ford key cache hit — dedup resolved via cross-batch lookup")
	} else {
		log.Debug().
			Str("ford_checksum", keyHex).
			Int("cache_size", size).
			Msg("Ford key cache miss — no cached key for fordChecksum")
	}
	return v, ok
}

// Len returns the number of cached keys. Diagnostic only.
func (c *FordKeyCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

// FordChecksumOf computes the `fordChecksum` used as the cache key:
// `0x01 || SHA1(ford_key)`. The 0x01 prefix matches the format that
// rustpush emits during Ford upload (`mmcs.rs` ford_signature
// construction) and that the MMCS download response returns for each
// deduplicated chunk.
func FordChecksumOf(fordKey []byte) []byte {
	h := sha1.Sum(fordKey)
	out := make([]byte, 1+len(h))
	out[0] = 0x01
	copy(out[1:], h[:])
	return out
}
