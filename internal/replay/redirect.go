package replay

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

const maxReplayRedirects = 10

// replayRedirectCheck keeps every hop on the destination the operator named.
// Go strips Authorization/Cookie on a cross-host redirect but still forwards
// custom headers captured from HAR/PCAP (X-Api-Key and friends), and the final
// response is stored on the packet and written to the JSON report. Without a
// pin, one redirect could leak those headers to another host and pull that
// host's response into the report. This mirrors internal/engine/client.go.
func replayRedirectCheck(config *ReplayConfig) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !config.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxReplayRedirects {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		if len(via) == 0 {
			return nil
		}

		first := via[0].URL
		// Host carries the port: a jump from one service to another on the
		// same machine is still a different destination.
		if req.URL.Host != first.Host {
			return http.ErrUseLastResponse
		}
		// A same-host https -> http downgrade would send captured credentials
		// in cleartext, so the scheme is pinned too.
		if !strings.EqualFold(req.URL.Scheme, first.Scheme) {
			return http.ErrUseLastResponse
		}

		if config.DialControl != nil {
			// The dial hook inspects the resolved peer on a direct socket and
			// ProxyWithControl inspects the destination when a proxy is used.
			// Re-resolving the redirect name here is a second, fail-closed
			// check before the next request is allowed to leave.
			port := req.URL.Port()
			if port == "" {
				port = "80"
				if scheme := strings.ToLower(req.URL.Scheme); scheme == "https" || scheme == "wss" {
					port = "443"
				}
			}
			if err := authz.CheckDialTarget(req.Context(), req.URL.Hostname(), port, config.DialControl); err != nil {
				return err
			}
		}
		return nil
	}
}
