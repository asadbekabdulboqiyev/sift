package engine

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestBufferCaptureCapsEntries(t *testing.T) {
	b := NewBufferCapture(3, DefaultCaptureBodyBytes)
	for i := 0; i < 6; i++ {
		b.Record(CapturedResponse{Method: "GET", URL: "http://x", Status: 200, Body: []byte("ok")})
	}
	kept, dropped := b.Count()
	if kept != 3 {
		t.Errorf("kept = %d, want 3", kept)
	}
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
}

func TestBufferCaptureTruncatesBody(t *testing.T) {
	const bodyCap = 16
	b := NewBufferCapture(10, bodyCap)
	payload := strings.Repeat("A", 500)
	b.Record(CapturedResponse{Status: 200, Body: []byte(payload)})

	var out bytes.Buffer
	if err := b.Render(&out); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "16 bytes") {
		t.Errorf("expected truncated size note, got:\n%s", rendered)
	}
	if strings.Count(rendered, "A") > bodyCap {
		t.Error("body not truncated")
	}
}

func TestBufferCaptureBinaryBody(t *testing.T) {
	b := NewBufferCapture(1, 64)
	b.Record(CapturedResponse{Status: 200, Body: []byte{0xff, 0xfe, 0x00}})

	var out bytes.Buffer
	if err := b.Render(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "<binary 3 bytes>") {
		t.Errorf("binary marker missing:\n%s", out.String())
	}
}

func TestClassifyUnsupportedSchemeIsNotConnectionError(t *testing.T) {
	uerr := &url.Error{
		Op:  "Get",
		URL: "localhost:9000",
		Err: errors.New(`unsupported protocol scheme ""`),
	}
	res := classifyError(uerr, 0)
	if res.errName != errOther {
		t.Errorf("errName = %q, want %q", res.errName, errOther)
	}

	connRefused := &url.Error{Op: "Get", URL: "http://x", Err: &net.OpError{
		Op:  "dial",
		Err: syscall.ECONNREFUSED,
	}}
	res = classifyError(connRefused, 0)
	if res.errName != errConnection {
		t.Errorf("errName = %q, want %q", res.errName, errConnection)
	}
}
