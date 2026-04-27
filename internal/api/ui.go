package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:ui
var uiFS embed.FS

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	// Serve embedded UI files
	subFS, err := fs.Sub(uiFS, "ui")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	path := r.URL.Path

	// Serve index.html for root and SPA routes — do NOT pass these through
	// http.FileServer because it will 301-redirect explicit "/index.html"
	// requests to "./" (its canonical behavior), causing an infinite redirect
	// loop in browsers.
	if path == "/" || path == "/index.html" {
		data, err := fs.ReadFile(subFS, "index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}

	// Try to serve the file directly via FileServer (handles caching, MIME, etc.)
	f, err := subFS.Open(strings.TrimPrefix(path, "/"))
	if err != nil {
		// SPA fallback - serve index.html for unknown routes
		data, err := fs.ReadFile(subFS, "index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}
	f.Close()

	http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
}
