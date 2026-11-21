package dashboard

import "context"

// auditActor returns the authenticated subject to record on a scan audit
// entry. An empty result means the request carried no principal; authz then
// falls back to currentUser(), preserving the behavior of an unauthenticated
// (loopback) dashboard. This is the single conversion point for all scan
// handlers, mirroring the actor plumbing on the load-test path.
func auditActor(ctx context.Context) string {
	subject, _, ok := PrincipalAndRolesFromContext(ctx)
	if !ok {
		return "" // authz falls back to currentUser()
	}
	return subject
}
