package events

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// BlobStore writes content-addressed blobs under a single directory.
// Returned references look like "sha256:<hex>" and can be embedded in
// events to keep events.jsonl small.
type BlobStore struct {
	dir string
}

// NewBlobStore prepares dir for use; the directory is created if
// missing.
func NewBlobStore(dir string) (*BlobStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("blob: mkdir: %w", err)
	}
	return &BlobStore{dir: dir}, nil
}

// Write stores body and returns its content reference. If the blob
// already exists (deduplication via content hash), Write is a no-op
// that returns the existing reference.
func (b *BlobStore) Write(body []byte) (string, error) {
	sum := sha256.Sum256(body)
	hex := hex.EncodeToString(sum[:])
	ref := "sha256:" + hex
	path := filepath.Join(b.dir, hex+".txt")
	if _, err := os.Stat(path); err == nil {
		return ref, nil
	}
	// Write to tmp then rename so partial writes don't surface as
	// truncated blobs to other readers.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return "", fmt.Errorf("blob: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("blob: rename: %w", err)
	}
	return ref, nil
}

// WriteString is a convenience wrapper around Write.
func (b *BlobStore) WriteString(body string) (string, error) {
	return b.Write([]byte(body))
}

// Dir returns the directory blobs are written to.
func (b *BlobStore) Dir() string { return b.dir }

// BestEffortRef stores body and returns its reference, or "" when there
// is no store, nothing to store, or the store rejected the write.
//
// Instrumentation must never fail the thing it is describing: a blob we
// could not write yields an empty ref, exactly as the LLM recording
// decorator does. Emitters call this instead of handling the error
// themselves so the policy stays in one place.
func BestEffortRef(store *BlobStore, body []byte) string {
	if store == nil || len(body) == 0 {
		return ""
	}
	ref, err := store.Write(body)
	if err != nil {
		return ""
	}
	return ref
}
