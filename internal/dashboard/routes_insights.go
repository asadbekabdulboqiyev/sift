package dashboard

// insightsRoutes registers the insights/advisory endpoints and the 360-degree
// audit job API (including its SSE stream). Order is preserved from serveApp.
func insightsRoutes() []appRoute {
	return []appRoute{
		{path: "/api/insights/xray/capabilities", handler: (*Server).handleInsightsXRayCapabilities},
		{path: "/api/insights/twin/fit", handler: (*Server).handleInsightsTwinFit},
		{path: "/api/insights/twin/simulate", handler: (*Server).handleInsightsTwinSimulate},
		{path: "/api/insights/twin/compare", handler: (*Server).handleInsightsTwinCompare},
		{path: "/api/insights/twin/sensitivity", handler: (*Server).handleInsightsTwinSensitivity},
		{path: "/api/insights/twin/backtest", handler: (*Server).handleInsightsTwinBacktest},
		{path: "/api/insights/resources/assess", handler: (*Server).handleInsightsResourceAssessment},
		{path: "/api/insights/xray/correlate", handler: (*Server).handleInsightsXRayCorrelate},
		{path: "/api/insights/bounty/validate", handler: (*Server).handleInsightsBountyValidate},
		{path: "/api/insights/bounty/verify-upload", handler: (*Server).handleInsightsBountyVerifyUpload},
		{path: "/api/insights/bounty/status", handler: (*Server).handleInsightsBountyStatus},

		{path: "/api/audit-360", handler: (*Server).handleAudit360Start},
		{path: "/api/audit-360/status", handler: (*Server).handleAudit360Status},
		{path: "/api/audit-360/stream", handler: (*Server).handleAudit360Stream},
		{path: "/api/audit-360/download", handler: (*Server).handleAudit360Download},
	}
}
