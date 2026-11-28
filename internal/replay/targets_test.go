package replay

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

func TestReplayTargetsBaseURLAndCapturedURLs(t *testing.T) {
	cfg := &ReplayConfig{
		BaseURL:                   "https://staging.example.com:8443/replay",
		AllowOriginalDestinations: true,
	}
	packets := []*Packet{
		{Method: "GET", URL: "https://user:secret@api.example.com/v1/a?token=leak"},
		{Method: "POST", URL: "https://api.example.com/v1/b"},
		{Method: "GET", URL: ""}, // not replayable
		nil,
	}

	got, err := Targets(cfg, packets)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://staging.example.com:8443", "https://api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for _, target := range got {
		if strings.Contains(target, "secret") || strings.Contains(target, "token") {
			t.Errorf("audit target leaked credentials: %q", target)
		}
	}
}

func TestReplayTargetsPCAPOriginForm(t *testing.T) {
	cfg := &ReplayConfig{AllowOriginalDestinations: true}
	packets := []*Packet{
		{Method: "GET", URL: "/api/one", Headers: http.Header{"Host": []string{"internal.example:8080"}}},
		{Method: "GET", URL: "/api/two", DstIP: net.ParseIP("10.1.2.3"), DstPort: 9090},
	}

	got, err := Targets(cfg, packets)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://internal.example:8080", "http://10.1.2.3:9090"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

func TestReplayTargetsFailClosed(t *testing.T) {
	cases := map[string]struct {
		cfg     *ReplayConfig
		packets []*Packet
		want    string
	}{
		"no destination": {
			cfg:  &ReplayConfig{},
			want: "cannot derive any replay destination",
		},
		"origin form without authority": {
			cfg:     &ReplayConfig{AllowOriginalDestinations: true},
			packets: []*Packet{{Method: "GET", URL: "/api/one"}},
			want:    "no Host header or captured peer",
		},
		"unsupported scheme": {
			cfg:  &ReplayConfig{BaseURL: "ftp://example.com/replay"},
			want: "unsupported replay scheme",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Targets(tc.cfg, tc.packets)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestReplayOriginFormUsesCapturedAuthority(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/capture" {
			t.Errorf("path = %q, want /capture", r.URL.Path)
		}
	}))
	defer srv.Close()

	pkt := &Packet{
		Method:  http.MethodGet,
		URL:     "/capture",
		Headers: http.Header{"Host": []string{strings.TrimPrefix(srv.URL, "http://")}},
	}
	cfg := &ReplayConfig{
		AllowOriginalDestinations: true,
		Pacing:                    PacingTiming,
		RateMultiplier:            1000,
		MaxConcurrency:            1,
		DialControl:               authz.ApprovedPeersControl(net.ParseIP("127.0.0.1")),
	}
	runOnePacket(t, pkt, cfg)
	if got := hits.Load(); got != 1 {
		t.Fatalf("captured-authority target saw %d requests, want 1", got)
	}
}

func TestReplayTargetsBaseURLWithoutOriginalDestinations(t *testing.T) {
	cfg := &ReplayConfig{
		BaseURL:                   "https://staging.example.com/replay",
		AllowOriginalDestinations: false,
	}
	packets := []*Packet{
		{Method: "GET", URL: "http://captured.internal.example/a"},
	}

	got, err := Targets(cfg, packets)
	if err != nil {
		t.Fatal(err)
	}
	// With a base override the captured URLs are never emitted, so they must
	// not become approvals either. The caller passes only filtered packets.
	if !reflect.DeepEqual(got, []string{"https://staging.example.com"}) {
		t.Fatalf("targets = %v", got)
	}
}
