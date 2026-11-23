package main

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// replayDialControl turns the operator-supplied --base-url into the socket-level
// approval used by every replay hop. Classify resolves the named destination
// once; authz.DialControl re-applies that class to the address each socket
// actually connects to, so DNS rebinding or a redirect cannot turn an approved
// public target into a request to loopback, RFC1918 space or metadata.
//
// The base URL is the explicit operator approval for this replay CLI (there is
// no importable gate builder here: cmd/sift is a separate main package). An
// empty base URL means no destination was named, so the hook stays nil and the
// historical direct behavior is preserved.
func replayDialControl(baseURL string) (func(network, address string, c syscall.RawConn) error, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target, err := authz.Classify(ctx, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("classify --base-url: %w", err)
	}
	// Instance metadata hands out temporary IAM credentials to anything that
	// can reach it. The shared policy never unlocks it by class, so this
	// narrower gate must not approve it either.
	if target.Class() == authz.ClassMetadata {
		return nil, fmt.Errorf("refusing to replay to cloud instance metadata (%s)", target.Host)
	}
	return authz.DialControl(target.Class()), nil
}
