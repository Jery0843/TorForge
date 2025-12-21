// Package api provides REST API for TorForge
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
)

// Server provides the API server
type Server struct {
	cfg      *config.APIConfig
	server   *http.Server
	handlers *Handlers
	mu       sync.RWMutex
	running  bool
}

// Handlers holds the API handlers and references to proxy components
type Handlers struct {
	OnNewCircuit   func() error
	OnGetStatus    func() (*StatusResponse, error)
	OnGetCircuits  func() ([]CircuitInfo, error)
	OnAddBypass    func(rule BypassRuleRequest) error
	OnRemoveBypass func(name string) error
	OnStop         func() error
}

// StatusResponse represents the proxy status
type StatusResponse struct {
	Running        bool   `json:"running"`
	Uptime         string `json:"uptime"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	ExitIP         string `json:"exit_ip"`
	ActiveCircuits int    `json:"active_circuits"`
	BytesSent      int64  `json:"bytes_sent"`
	BytesRecv      int64  `json:"bytes_recv"`
	DNSQueries     int64  `json:"dns_queries"`
	Version        string `json:"version"`
}

// CircuitInfo represents circuit information
type CircuitInfo struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	CreatedAt  string   `json:"created_at"`
	AgeSeconds int64    `json:"age_seconds"`
	BytesSent  int64    `json:"bytes_sent"`
	BytesRecv  int64    `json:"bytes_recv"`
	Path       []string `json:"path"`
	ExitNode   string   `json:"exit_node"`
}

// BypassRuleRequest represents a bypass rule request
type BypassRuleRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // domain, cidr, protocol
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // bypass, block, tor
}

// NewServer creates a new API server
func NewServer(cfg *config.APIConfig, handlers *Handlers) *Server {
	return &Server{
		cfg:      cfg,
		handlers: handlers,
	}
}

// Start starts the API server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	log := logger.WithComponent("api")

	mux := http.NewServeMux()

	// Middleware
	handler := s.authMiddleware(mux)
	handler = s.loggingMiddleware(handler)
	handler = s.corsMiddleware(handler)

	// Routes
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/circuits", s.handleCircuits)
	mux.HandleFunc("/api/v1/circuit/new", s.handleNewCircuit)
	mux.HandleFunc("/api/v1/bypass", s.handleBypass)
	mux.HandleFunc("/api/v1/stop", s.handleStop)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/events", s.handleEventStream)

	s.server = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		var err error
		if s.cfg.TLSEnabled {
			log.Info().
				Str("addr", s.cfg.ListenAddr).
				Msg("API server starting with TLS")
			err = s.server.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			log.Info().
				Str("addr", s.cfg.ListenAddr).
				Msg("API server starting")
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("API server error")
		}
	}()

	s.running = true
	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return err
	}

	s.running = false
	return nil
}

// Middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		if s.cfg.AuthToken != "" {
			token := r.Header.Get("Authorization")
			expected := "Bearer " + s.cfg.AuthToken

			if token != expected {
				s.writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)

		logger.Log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("request")
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Handlers
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.handlers.OnGetStatus == nil {
		s.writeError(w, http.StatusNotImplemented, "not implemented")
		return
	}

	status, err := s.handlers.OnGetStatus()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleCircuits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.handlers.OnGetCircuits == nil {
		s.writeError(w, http.StatusNotImplemented, "not implemented")
		return
	}

	circuits, err := s.handlers.OnGetCircuits()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"circuits": circuits,
		"count":    len(circuits),
	})
}

func (s *Server) handleNewCircuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.handlers.OnNewCircuit == nil {
		s.writeError(w, http.StatusNotImplemented, "not implemented")
		return
	}

	if err := s.handlers.OnNewCircuit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	logger.Audit("api").Str("action", "new_circuit").Msg("new circuit requested via API")

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "new circuit requested",
	})
}

func (s *Server) handleBypass(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req BypassRuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if s.handlers.OnAddBypass == nil {
			s.writeError(w, http.StatusNotImplemented, "not implemented")
			return
		}

		if err := s.handlers.OnAddBypass(req); err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		logger.Audit("api").
			Str("action", "add_bypass").
			Str("name", req.Name).
			Str("pattern", req.Pattern).
			Msg("bypass rule added via API")

		s.writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"message": "bypass rule added",
		})

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			s.writeError(w, http.StatusBadRequest, "name parameter required")
			return
		}

		if s.handlers.OnRemoveBypass == nil {
			s.writeError(w, http.StatusNotImplemented, "not implemented")
			return
		}

		if err := s.handlers.OnRemoveBypass(name); err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"message": "bypass rule removed",
		})

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.handlers.OnStop == nil {
		s.writeError(w, http.StatusNotImplemented, "not implemented")
		return
	}

	logger.Audit("api").Str("action", "stop").Msg("stop requested via API")

	if err := s.handlers.OnStop(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "stopping",
	})
}

// handleEventStream provides Server-Sent Events (SSE) for real-time status updates
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Send heartbeat events
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if s.handlers.OnGetStatus != nil {
				status, err := s.handlers.OnGetStatus()
				if err == nil {
					data, _ := json.Marshal(status)
					fmt.Fprintf(w, "event: status\ndata: %s\n\n", data)
					flusher.Flush()
				}
			}
		}
	}
}

// Helper functions
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}
