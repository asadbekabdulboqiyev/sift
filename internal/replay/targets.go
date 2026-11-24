package replay

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ReplayTargets returns every destination the engine can emit for this run,
// normalized to scheme://host[:port] so the authorization gate classifies the
// host exactly once and can pin the socket to the addresses it approved.
//
// Two sources matter:
//
//   - --base-url is the explicit operator override and is always included;
//   - with --allow-original-destinations, every absolute URL in the FILTERED
//     packet set is included as well. A PCAP origin-form URL is resolved from
//     its captured Host header, falling back to the captured peer address.
//
// Returning an error when nothing can be derived is deliberate: a replay with
// no gate derivation is a replay with no socket control, which is precisely the
// egress path this API exists to close.
func ReplayTargets(config *ReplayConfig, packets []*Packet) ([]string, error) {
	if config == nil {
		return nil, fmt.Errorf("cannot derive replay destinations: nil replay config")
	}

	seen := make(map[string]bool)
	var out []string
	add := func(raw string) error {
		target, err := normalizeReplayTarget(raw)
		if err != nil {
			return err
		}
		if target == "" || seen[target] {
			return nil
		}
		seen[target] = true
		out = append(out, target)
		return nil
	}

	if base := strings.TrimSpace(config.BaseURL); base != "" {
		if err := add(base); err != nil {
			return nil, fmt.Errorf("derive destination from --base-url: %w", err)
		}
	}

	if config.AllowOriginalDestinations {
		for _, pkt := range packets {
			if pkt == nil || strings.TrimSpace(pkt.Method) == "" || strings.TrimSpace(pkt.URL) == "" {
				continue // not a replayable HTTP request
			}
			raw, err := capturedDestination(pkt)
			if err != nil {
				return nil, err
			}
			if err := add(raw); err != nil {
				return nil, fmt.Errorf("derive destination from captured URL: %w", err)
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("cannot derive any replay destination: set --base-url or --allow-original-destinations with absolute captured URLs")
	}
	return out, nil
}

// capturedDestination makes a captured URL usable as a gate target. Absolute
// HAR URLs are already usable; PCAP origin-form requests carry only a path, so
// the authority has to come from the captured Host header or the packet's peer.
func capturedDestination(pkt *Packet) (string, error) {
	raw := strings.TrimSpace(pkt.URL)
	if strings.Contains(raw, "://") {
		return raw, nil
	}

	authority := ""
	if pkt.Headers != nil {
		authority = strings.TrimSpace(pkt.Headers.Get("Host"))
	}
	if authority == "" && pkt.DstIP != nil {
		port := pkt.DstPort
		if port <= 0 {
			// The PCAP stream parser records plaintext HTTP, so 80 is the
			// captured default. A Host header with an explicit port wins above.
			port = 80
		}
		authority = net.JoinHostPort(pkt.DstIP.String(), strconv.Itoa(port))
	}
	if authority == "" {
		return "", fmt.Errorf("cannot derive replay destination for %q: origin-form URL has no Host header or captured peer", redactURLForError(raw))
	}
	return "http://" + authority + raw, nil
}

// normalizeReplayTarget strips path, query, fragment and userinfo. The gate
// needs only the origin, and audit records must never inherit credentials from
// a captured URL. Bare host[:port] values are treated as http, matching the
// engine's default scheme.
func normalizeReplayTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("parse destination %q: %w", redactURLForError(raw), err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("destination %q has no host", redactURLForError(raw))
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported replay scheme %q in %q", scheme, redactURLForError(raw))
	}
	return scheme + "://" + u.Host, nil
}
