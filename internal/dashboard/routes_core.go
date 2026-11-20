package dashboard

// coreRoutes covers the live snapshot/run control plane, attestation,
// certificate, admin and demo-store endpoints. The order mirrors the original
// serveApp switch, including /api/certificate/generate sharing the issue
// handler and /api/certificate/download/<name> being a prefix match.
func coreRoutes() []appRoute {
	return []appRoute{
		{path: "/ws", handler: (*Server).handleWebSocket},
		{path: "/api/snapshot", handler: (*Server).handleSnapshot},
		{path: "/api/run", handler: (*Server).handleRunAPI},
		{path: "/api/history", handler: (*Server).handleHistory},
		{path: "/api/run/start", handler: (*Server).handleStartRun},
		{path: "/api/run/stop", handler: (*Server).handleStopRun},

		{path: "/api/attestation", handler: (*Server).handleAttestationGet},
		{path: "/api/attestation/download", handler: (*Server).handleAttestationDownload},
		{path: "/api/attestation/verify", handler: (*Server).handleAttestationVerify},
		{path: "/api/attestation/verify-upload", handler: (*Server).handleAttestationVerifyUpload},

		{path: "/api/certificate/verify", handler: (*Server).handleCertificateVerify},
		{path: "/api/certificate/issue", handler: (*Server).handleCertificateIssue},
		{prefix: "/api/certificate/download/", handler: (*Server).handleCertificateDownload},
		{path: "/api/certificate/history", handler: (*Server).handleCertificateHistory},
		{path: "/api/certificate/generate", handler: (*Server).handleCertificateIssue},

		{path: "/api/admin/status", handler: (*Server).handleAdminStatus},
		{path: "/api/admin/unlock", handler: (*Server).handleAdminUnlock},
		{path: "/api/admin/lock", handler: (*Server).handleAdminLock},
		{path: "/api/version", handler: (*Server).handleVersion},

		{path: "/api/demo-store/start", handler: (*Server).handleDemoStoreStart},
		{path: "/api/demo-store/stop", handler: (*Server).handleDemoStoreStop},
		{path: "/api/demo-store/status", handler: (*Server).handleDemoStoreStatus},
	}
}
