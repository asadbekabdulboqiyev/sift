package dashboard

import (
	"net/http"
)

const (
	insightsMaxBody = 4 << 20
	triageMaxBody   = 2 << 20
)

func insightsJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	writeJSON(w, v)
}
