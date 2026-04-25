package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Recorder is the interface every emitter writes through. Returning
// an error matters for the JSONL writer; tests can use Nop to ignore
// failures entirely.
type Recorder interface {
	Emit(e Event) error
	Close() error
}

// Nop is a no-op recorder. Useful in tests and in callers that want
// the instrumentation hooks but no file output.
type Nop struct{}

func (Nop) Emit(Event) error { return nil }
func (Nop) Close() error     { return nil }

// JSONLRecorder writes one event per line to a JSONL file with
// O_APPEND. Seq is recovered from the existing file on open so
// resumed runs continue numbering monotonically.
type JSONLRecorder struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	seq  int64
	now  func() time.Time // injectable for tests
	path string
}

// NewJSONLRecorder opens (or creates) path for append. If the file
// already contains events, seq starts from max(seq)+1. Parent dir is
// created if missing.
func NewJSONLRecorder(path string) (*JSONLRecorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("events: mkdir: %w", err)
	}
	maxSeq, err := scanMaxSeq(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("events: open %s: %w", path, err)
	}
	return &JSONLRecorder{
		f:    f,
		w:    bufio.NewWriter(f),
		seq:  maxSeq,
		now:  time.Now,
		path: path,
	}, nil
}

// Emit assigns a seq + timestamp and writes a single JSONL line.
// Caller-provided values for Seq and Time are overwritten — the
// recorder owns those fields.
func (r *JSONLRecorder) Emit(e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.Seq = r.seq
	e.Time = r.now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("events: marshal: %w", err)
	}
	if _, err := r.w.Write(b); err != nil {
		return fmt.Errorf("events: write: %w", err)
	}
	if _, err := r.w.WriteString("\n"); err != nil {
		return fmt.Errorf("events: write nl: %w", err)
	}
	// Flush each event to disk — events are facts and an event we
	// failed to persist is worse than the throughput cost.
	if err := r.w.Flush(); err != nil {
		return fmt.Errorf("events: flush: %w", err)
	}
	return nil
}

func (r *JSONLRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.w.Flush(); err != nil {
		return err
	}
	return r.f.Close()
}

// Path returns the file path the recorder is writing to.
func (r *JSONLRecorder) Path() string { return r.path }

// scanMaxSeq reads existing JSONL lines and returns the highest seq
// it finds, or 0 if the file does not exist or is empty. Malformed
// lines are skipped — partial corruption shouldn't abort a new run.
func scanMaxSeq(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("events: stat: %w", err)
	}
	defer f.Close()

	var maxSeq int64
	br := bufio.NewReader(f)
	for {
		line, err := br.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			var probe struct {
				Seq int64 `json:"seq"`
			}
			if jsonErr := json.Unmarshal([]byte(line), &probe); jsonErr == nil {
				if probe.Seq > maxSeq {
					maxSeq = probe.Seq
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return maxSeq, fmt.Errorf("events: scan: %w", err)
		}
	}
	return maxSeq, nil
}
