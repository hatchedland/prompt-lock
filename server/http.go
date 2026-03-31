package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/rajanyadav/promptlock"
	"github.com/rajanyadav/promptlock/detector"
	"github.com/rajanyadav/promptlock/vault"
)

const maxBodySize = 1 << 20 // 1MB

// HTTPServer serves the PromptLock REST/JSON API.
type HTTPServer struct {
	shield *promptlock.Shield
	mux    *http.ServeMux
}

// NewHTTPServer creates an HTTP server wrapping the given Shield.
func NewHTTPServer(shield *promptlock.Shield) *HTTPServer {
	s := &HTTPServer{shield: shield, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /v1/protect", s.handleProtect)
	s.mux.HandleFunc("POST /v1/protect/detailed", s.handleProtectDetailed)
	s.mux.HandleFunc("POST /v1/verify-context", s.handleVerifyContext)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	return s
}

// Handler returns the http.Handler for this server.
func (s *HTTPServer) Handler() http.Handler {
	return s.mux
}

// --- Request/Response types ---

type protectRequest struct {
	Input string `json:"input"`
}

type protectResponse struct {
	Output     string              `json:"output,omitempty"`
	Blocked    bool                `json:"blocked"`
	Score      int                 `json:"score"`
	Verdict    string              `json:"verdict"`
	Violations []violationResponse `json:"violations,omitempty"`
}

type scanResultResponse struct {
	Output     string                  `json:"output,omitempty"`
	Clean      bool                    `json:"clean"`
	Score      int                     `json:"score"`
	Verdict    string                  `json:"verdict"`
	Violations []violationResponse     `json:"violations"`
	Redactions []redactedEntityResponse `json:"redactions"`
	Delimiter  string                  `json:"delimiter,omitempty"`
	LatencyMs  int64                   `json:"latency_ms"`
}

type violationResponse struct {
	Rule       string  `json:"rule"`
	Category   string  `json:"category"`
	Severity   string  `json:"severity"`
	Matched    string  `json:"matched"`
	Confidence float64 `json:"confidence"`
	Offset     int     `json:"offset"`
	Weight     int     `json:"weight"`
}

type redactedEntityResponse struct {
	Type        string `json:"type"`
	Placeholder string `json:"placeholder"`
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
}

type verifyContextRequest struct {
	Chunks []string `json:"chunks"`
}

type verifyContextResponse struct {
	CleanChunks  []string `json:"clean_chunks"`
	BlockedCount int      `json:"blocked_count"`
}

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// --- Handlers ---

func (s *HTTPServer) handleProtect(w http.ResponseWriter, r *http.Request) {
	var req protectRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input is required")
		return
	}

	output, err := s.shield.Protect(r.Context(), req.Input)
	if err != nil {
		var plErr *promptlock.PromptLockError
		if errors.As(err, &plErr) {
			resp := protectResponse{
				Blocked:    true,
				Score:      plErr.Score,
				Verdict:    plErr.Verdict.String(),
				Violations: mapViolations(plErr.Violations),
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, protectResponse{
		Output:  output,
		Blocked: false,
		Score:   0,
		Verdict: "clean",
	})
}

func (s *HTTPServer) handleProtectDetailed(w http.ResponseWriter, r *http.Request) {
	var req protectRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input is required")
		return
	}

	result, err := s.shield.ProtectWithResult(r.Context(), req.Input)
	if err != nil {
		var plErr *promptlock.PromptLockError
		if errors.As(err, &plErr) {
			resp := scanResultResponse{
				Clean:      false,
				Score:      plErr.Score,
				Verdict:    plErr.Verdict.String(),
				Violations: mapViolations(plErr.Violations),
				Redactions: []redactedEntityResponse{},
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := scanResultResponse{
		Output:     result.Output,
		Clean:      result.Clean,
		Score:      result.Score,
		Verdict:    result.Verdict.String(),
		Violations: mapViolations(result.Violations),
		Redactions: mapRedactions(result.Redactions),
		Delimiter:  result.Delimiter,
		LatencyMs:  result.Latency.Milliseconds(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *HTTPServer) handleVerifyContext(w http.ResponseWriter, r *http.Request) {
	var req verifyContextRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Chunks) == 0 {
		writeError(w, http.StatusBadRequest, "chunks is required")
		return
	}

	clean, err := s.shield.VerifyContext(r.Context(), req.Chunks)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, verifyContextResponse{
		CleanChunks:  clean,
		BlockedCount: len(req.Chunks) - len(clean),
	})
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Version: "1.0.0",
	})
}

// --- Helpers ---

func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func mapViolations(vs []detector.Violation) []violationResponse {
	if len(vs) == 0 {
		return []violationResponse{}
	}
	result := make([]violationResponse, len(vs))
	for i, v := range vs {
		result[i] = violationResponse{
			Rule:       v.Rule,
			Category:   v.Category.String(),
			Severity:   v.Severity.String(),
			Matched:    v.Matched,
			Confidence: v.Confidence,
			Offset:     v.Offset,
			Weight:     v.Weight,
		}
	}
	return result
}

func mapRedactions(rs []vault.RedactedEntity) []redactedEntityResponse {
	if len(rs) == 0 {
		return []redactedEntityResponse{}
	}
	result := make([]redactedEntityResponse, len(rs))
	for i, r := range rs {
		result[i] = redactedEntityResponse{
			Type:        r.Type.String(),
			Placeholder: r.Placeholder,
			Offset:      r.Offset,
			Length:       r.Length,
		}
	}
	return result
}
