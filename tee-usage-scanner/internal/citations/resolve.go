package citations

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Errors returned by Resolve / Validate.
var (
	ErrNotResolvable    = errors.New("citation: not resolvable")
	ErrFileMissing      = errors.New("citation: file not found")
	ErrLineOutOfRange   = errors.New("citation: line out of range")
	ErrInvalidLineRange = errors.New("citation: invalid line range")
	ErrSHA256Mismatch   = errors.New("citation: sha256 drifted")
)

// Resolve reads File under repoRoot, computes byte offsets for the
// given line range, and returns a fully populated CitedBytes. The
// input is allowed to omit StartByte/EndByte/SHA256 — Resolve fills
// them in. Empty repoRoot is treated as "absolute paths only".
//
// Line range semantics: 1-indexed, inclusive. Lines are split on
// '\n'; a trailing newline at end-of-file does NOT produce a
// phantom empty final line. EndLine may equal the file's last
// non-empty line.
func Resolve(c CitedBytes, repoRoot string) (CitedBytes, error) {
	if !c.Valid() {
		return c, fmt.Errorf("%w: %+v", ErrNotResolvable, c)
	}
	abs := c.File
	if !filepath.IsAbs(abs) && repoRoot != "" {
		abs = filepath.Join(repoRoot, c.File)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return c, fmt.Errorf("%w: %s", ErrFileMissing, c.File)
		}
		return c, err
	}
	startByte, endByte, err := lineRangeToByteRange(body, c.StartLine, c.EndLine)
	if err != nil {
		return c, err
	}
	region := body[startByte:endByte]
	sum := sha256.Sum256(region)

	c.StartByte = int64(startByte)
	c.EndByte = int64(endByte)
	c.SHA256 = hex.EncodeToString(sum[:])
	return c, nil
}

// Validate re-reads the file and recomputes the byte range + sha256
// for the recorded line range, comparing the result against the
// citation's stored fields. A returned nil error means the citation
// still points at the same bytes it pointed at when it was made.
//
// Behavior on input:
//   - If c is not Resolved (no recorded SHA256), Validate calls
//     Resolve and returns nil iff resolution succeeds. This lets
//     stats consume legacy hypotheses that were written before the
//     citation contract existed.
//   - If c IS resolved, Validate insists the recomputed sha256
//     match c.SHA256 exactly. Any mismatch returns ErrSHA256Mismatch.
//
// Byte offsets in c are NOT used for the comparison — they are
// re-derived from the line range. Hand-written byte offsets that
// disagree with the line range produce a sha256 mismatch, which
// is the right answer.
func Validate(c CitedBytes, repoRoot string) error {
	if !c.Valid() {
		return fmt.Errorf("%w: %+v", ErrNotResolvable, c)
	}
	resolved, err := Resolve(c, repoRoot)
	if err != nil {
		return err
	}
	if !c.Resolved() {
		// Legacy citation without recorded hash; resolution alone
		// is the success criterion.
		return nil
	}
	if resolved.SHA256 != c.SHA256 {
		return fmt.Errorf("%w: file=%s lines=%d-%d", ErrSHA256Mismatch,
			c.File, c.StartLine, c.EndLine)
	}
	return nil
}

// lineRangeToByteRange returns half-open byte offsets [start, end)
// covering the inclusive 1-indexed line range. The end offset
// includes the terminating newline of EndLine when present, so
// citing line N produces bytes that, when written back to a file,
// reproduce the original line including its trailing newline.
func lineRangeToByteRange(body []byte, startLine, endLine int) (int, int, error) {
	if startLine < 1 || endLine < startLine {
		return 0, 0, ErrInvalidLineRange
	}
	curLine := 1
	startOff := -1
	endOff := -1
	for i := 0; i < len(body); i++ {
		if curLine == startLine && startOff == -1 {
			startOff = i
		}
		if body[i] == '\n' {
			if curLine == endLine {
				endOff = i + 1 // include the newline
				break
			}
			curLine++
		}
	}
	// Handle files that don't end with a newline.
	if startOff == -1 && curLine == startLine {
		startOff = len(body)
	}
	if endOff == -1 {
		// EndLine might be the final line of a file with no
		// trailing newline; in that case the cited region runs to
		// EOF.
		if curLine >= endLine {
			endOff = len(body)
		} else {
			return 0, 0, fmt.Errorf("%w: file has %d lines, requested %d-%d",
				ErrLineOutOfRange, curLine, startLine, endLine)
		}
	}
	if startOff == -1 {
		return 0, 0, fmt.Errorf("%w: start line %d beyond file (%d lines)",
			ErrLineOutOfRange, startLine, curLine)
	}
	return startOff, endOff, nil
}
