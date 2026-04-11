package connector

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

func TestFordChecksumFormat(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	got := FordChecksumOf(key)
	if len(got) != 21 {
		t.Fatalf("fordChecksum length: want 21, got %d", len(got))
	}
	if got[0] != 0x01 {
		t.Fatalf("fordChecksum prefix: want 0x01, got 0x%02x", got[0])
	}
	h := sha1.Sum(key)
	if !bytes.Equal(got[1:], h[:]) {
		t.Fatalf("fordChecksum body mismatch: want %x, got %x", h[:], got[1:])
	}
}

func TestFordKeyCacheRoundTrip(t *testing.T) {
	cache := NewFordKeyCache()
	key := bytes.Repeat([]byte{0x42}, 32)
	cache.Register(key)

	checksum := FordChecksumOf(key)
	got, ok := cache.Lookup(checksum)
	if !ok {
		t.Fatalf("cache miss for registered key")
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("cache value mismatch: want %x, got %x", key, got)
	}
}

func TestFordKeyCacheCrossBatchSimulation(t *testing.T) {
	// Upload batch A registers key K_a; batch B later tries to download
	// a deduplicated blob encrypted with K_a (not with B's own key).
	// The cache must return K_a when consulted with fordChecksum(K_a).
	cache := NewFordKeyCache()
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	keyB := bytes.Repeat([]byte{0xBB}, 32)
	cache.Register(keyA)
	cache.Register(keyB)

	checksumA := FordChecksumOf(keyA)
	got, ok := cache.Lookup(checksumA)
	if !ok {
		t.Fatalf("cross-batch cache miss")
	}
	if !bytes.Equal(got, keyA) {
		t.Fatalf("cross-batch lookup returned wrong key: want %x, got %x", keyA, got)
	}

	// Different checksums produce different hits — no cross-pollution.
	checksumB := FordChecksumOf(keyB)
	gotB, _ := cache.Lookup(checksumB)
	if bytes.Equal(gotB, keyA) {
		t.Fatalf("lookup for keyB's checksum returned keyA — cache is broken")
	}
}

func TestFordKeyCacheIgnoresEmpty(t *testing.T) {
	cache := NewFordKeyCache()
	cache.Register(nil)
	cache.Register([]byte{})
	if cache.Len() != 0 {
		t.Fatalf("empty key should be ignored, cache len = %d", cache.Len())
	}
	if _, ok := cache.Lookup(nil); ok {
		t.Fatalf("empty checksum should miss")
	}
}

func TestFordKeyCacheRegisterIdempotent(t *testing.T) {
	cache := NewFordKeyCache()
	key := bytes.Repeat([]byte{0x11}, 32)
	cache.Register(key)
	cache.Register(key)
	cache.Register(key)
	if cache.Len() != 1 {
		t.Fatalf("duplicate registrations: want 1 entry, got %d", cache.Len())
	}
}

func TestFordKeyCacheIsolatesCallerMutation(t *testing.T) {
	cache := NewFordKeyCache()
	key := bytes.Repeat([]byte{0xCC}, 32)
	cache.Register(key)

	// Mutate the original — cache must not observe the change.
	key[0] = 0xFF

	checksum := FordChecksumOf(bytes.Repeat([]byte{0xCC}, 32))
	got, ok := cache.Lookup(checksum)
	if !ok {
		t.Fatalf("cache miss after caller mutation")
	}
	if got[0] == 0xFF {
		t.Fatalf("cache aliased the caller's slice")
	}
}
