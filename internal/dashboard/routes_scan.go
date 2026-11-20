package dashboard

// scanRoutes registers the defensive and offensive scanner endpoints. Each
// handler performs its own method and origin checks; dispatch order is kept
// identical to the original serveApp switch.
func scanRoutes() []appRoute {
	return []appRoute{
		{path: "/api/owasp/scan", handler: (*Server).handleOWASPScan},

		{path: "/api/pentest/scan", handler: (*Server).handlePentestScan},
		{path: "/api/pentest/latest", handler: (*Server).handlePentestLatest},
		{path: "/api/crawl/scan", handler: (*Server).handleCrawlScan},
		{path: "/api/fuzz/scan", handler: (*Server).handleFuzzScan},
		{path: "/api/subdomain/scan", handler: (*Server).handleSubdomainScan},
		{path: "/api/portscan", handler: (*Server).handlePortScan},
		{path: "/api/dirbust", handler: (*Server).handleDirBust},
		{path: "/api/sslscan", handler: (*Server).handleSSLScan},
		{path: "/api/jwt/scan", handler: (*Server).handleJWTScan},
		{path: "/api/graphql/scan", handler: (*Server).handleGraphQLScan},
		{path: "/api/websocket/scan", handler: (*Server).handleWebSocketScan},
	}
}
