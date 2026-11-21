package engine

import (
	"fmt"
	"io"
	"sync"
	"unicode/utf8"
)

// DefaultCaptureBodyBytes is the per-entry body limit used when none is configured.
const DefaultCaptureBodyBytes = 2048

// CapturedResponse is one recorded HTTP exchange for reporting or inspection.
type CapturedResponse struct {
	Step   string
	Method string
	URL    string
	Status int
	Err    string
	Body   []byte
}

// ResponseCapture receives response records produced during a load run.
type ResponseCapture interface {
	Record(CapturedResponse)
}

// BufferCapture is a concurrency-safe ResponseCapture that keeps a bounded number of responses.
type BufferCapture struct {
	mu           sync.Mutex
	maxEntries   int
	maxBodyBytes int
	entries      []CapturedResponse
	dropped      int
}

// NewBufferCapture creates a BufferCapture keeping at most maxEntries responses with bodies capped at maxBodyBytes.
func NewBufferCapture(maxEntries, maxBodyBytes int) *BufferCapture {
	if maxEntries < 1 {
		maxEntries = 1
	}
	if maxBodyBytes < 1 {
		maxBodyBytes = DefaultCaptureBodyBytes
	}
	return &BufferCapture{
		maxEntries:   maxEntries,
		maxBodyBytes: maxBodyBytes,
	}
}

// Record adds one response, dropping it when the entry cap is reached.
func (b *BufferCapture) Record(r CapturedResponse) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) >= b.maxEntries {
		b.dropped++
		return
	}
	if len(r.Body) > b.maxBodyBytes {
		r.Body = r.Body[:b.maxBodyBytes]
	}
	b.entries = append(b.entries, r)
}

// Count returns the number of kept responses and the number dropped at the cap.
func (b *BufferCapture) Count() (kept, dropped int) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries), b.dropped
}

// Render writes a human-readable summary of all kept responses to w.
func (b *BufferCapture) Render(w io.Writer) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, err := fmt.Fprintf(w, "Captured responses: %d", len(b.entries)); err != nil {
		return err
	}
	if b.dropped > 0 {
		if _, err := fmt.Fprintf(w, " (%d more dropped beyond cap)", b.dropped); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	for i, e := range b.entries {
		if _, err := fmt.Fprintf(w, "\n[%03d] %s %s -> %d", i+1, e.Method, e.URL, e.Status); err != nil {
			return err
		}
		if e.Step != "" {
			if _, err := fmt.Fprintf(w, " | step=%s", e.Step); err != nil {
				return err
			}
		}
		if e.Err != "" {
			if _, err := fmt.Fprintf(w, " | err=%s", e.Err); err != nil {
				return err
			}
		}
		bodyNote := "empty"
		if len(e.Body) > 0 {
			bodyNote = fmt.Sprintf("%d bytes", len(e.Body))
		}
		if _, err := fmt.Fprintf(w, " | body: %s\n", bodyNote); err != nil {
			return err
		}
		if len(e.Body) > 0 {
			if utf8.Valid(e.Body) {
				if _, err := w.Write(e.Body); err != nil {
					return err
				}
				if _, err := fmt.Fprintln(w); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(w, "<binary %d bytes>\n", len(e.Body)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
