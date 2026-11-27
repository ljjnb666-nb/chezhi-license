package main

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type apiEnvelope struct {
	Version   string       `json:"version"`
	RequestID string       `json:"request_id"`
	Data      *licenseData `json:"data,omitempty"`
	Error     *apiError    `json:"error,omitempty"`
}
type apiError struct {
	Code string `json:"code"`
}
type licenseData struct {
	Valid     bool       `json:"valid"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func writeAPI(w http.ResponseWriter, status int, id string, data *licenseData, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	result := apiEnvelope{Version: "v1", RequestID: id, Data: data}
	if code != "" {
		result.Error = &apiError{Code: code}
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (w Web) licenseAPI(rw http.ResponseWriter, r *http.Request) {
	settings, _ := r.Context().Value(serverRequestKey{}).(serverRequest)
	id := settings.id
	if id == "" {
		id = randomToken()[:32]
	}
	fail := func(status int, code string) { writeAPI(rw, status, id, nil, code) }
	path := r.URL.Path
	if path != "/api/v1/licenses/activate" && path != "/api/v1/licenses/validate" {
		fail(404, "not_found")
		return
	}
	if len(r.Header.Values("Origin")) != 0 || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Referer") != "" {
		fail(403, "browser_origin_forbidden")
		return
	}
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", "POST")
		fail(405, "method_not_allowed")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		fail(415, "json_required")
		return
	}
	if !w.consumeLicenseBudget(rw, r, fail) {
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		fail(413, "body_too_large")
		return
	}
	var request demoRequest
	if err != nil || !utf8.Valid(body) || uniqueJSON(body) != nil {
		fail(400, "invalid_json")
		return
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		fail(400, "invalid_json")
		return
	}
	if len(request.Key) == 0 || len(request.Key) > 100 || len(request.Device) > 200 || strings.TrimSpace(request.Device) == "" {
		fail(400, "invalid_input")
		return
	}
	result, err := w.s.checkLicense(r.Context(), request.Key, request.Device, path == "/api/v1/licenses/activate")
	if err != nil {
		fail(503, "unavailable")
		return
	}
	status := result.Reason
	if result.Valid {
		status = "valid"
	}
	writeAPI(rw, 200, id, &licenseData{Valid: result.Valid, Status: status, ExpiresAt: result.ExpiresAt}, "")
}

func (w Web) consumeLicenseBudget(rw http.ResponseWriter, r *http.Request, fail func(int, string)) bool {
	settings, shared := r.Context().Value(serverRequestKey{}).(serverRequest)
	var allowed bool
	if shared {
		var err error
		allowed, err = w.s.pg.allowShared(r.Context(), "license", settings.source, settings.config.publicRate, settings.config.licenseRate)
		if err != nil {
			fail(503, "unavailable")
			return false
		}
	} else {
		allowed = w.s.allowActivation()
	}
	if !allowed {
		rw.Header().Set("Retry-After", "60")
		fail(429, "rate_limited")
	}
	return allowed
}
