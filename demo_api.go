package main

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
)

// The purchase page exposes only public, non-sensitive support information.
func (w Web) purchase(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", "GET")
		http.Error(rw, "method not allowed", 405)
		return
	}
	state, plans, err := w.s.readView(r.Context(), false)
	if err != nil {
		http.Error(rw, "service unavailable", 503)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := purchasePage.Execute(rw, struct {
		QQ    string
		Plans []Plan
	}{state.QQ, plans}); err != nil {
		return
	}
}

type demoRequest struct {
	Key    string `json:"key"`
	Device string `json:"device"`
}
type demoResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
	Expiry string `json:"expiry,omitempty"`
}

// Local, non-browser JSON endpoint for the separate test client. Same Store
// and shared rate budget as the browser activation route. Never grants network access.
func (w Web) demoActivate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", "POST")
		http.Error(rw, "method not allowed", 405)
		return
	}
	// Native client only: browser Origin (including null) and Fetch Metadata rejected.
	if len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Sec-Fetch-Site")) != 0 || len(r.Header.Values("Referer")) != 0 {
		http.Error(rw, "browser request forbidden", 403)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(rw, "JSON required", 415)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req demoRequest
	if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF {
		http.Error(rw, "invalid JSON", 400)
		return
	}
	if !w.consumeLicenseBudget(rw, r, func(status int, _ string) { http.Error(rw, http.StatusText(status), status) }) {
		return
	}
	res, err := w.s.validateContext(r.Context(), req.Key, req.Device)
	if err != nil {
		http.Error(rw, "service unavailable", 503)
		return
	}
	out := demoResponse{Valid: res.Valid, Reason: res.Reason}
	if res.Valid {
		out.Expiry = "永久"
		if res.ExpiresAt != nil {
			out.Expiry = when(res.ExpiresAt) + "（北京时间）"
		}
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(rw).Encode(out)
}
