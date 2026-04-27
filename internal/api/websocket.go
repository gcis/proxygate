// Package api provides the REST API and WebSocket hub for the admin UI.
package api

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type WSHub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
	logger  *slog.Logger
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Admin UI is local-only
	},
}

func NewWSHub(logger *slog.Logger) *WSHub {
	return &WSHub{
		clients: make(map[*websocket.Conn]bool),
		logger:  logger,
	}
}

func (h *WSHub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("websocket upgrade failed", "error", err)
		return
	}

	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()

	h.logger.Info("websocket client connected", "remote", r.RemoteAddr)

	// Read loop to detect disconnects
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients, conn)
			h.mu.Unlock()
			conn.Close()
			h.logger.Info("websocket client disconnected")
		}()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

func (h *WSHub) Broadcast(msg WSMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for conn := range h.clients {
		if err := conn.WriteJSON(msg); err != nil {
			h.logger.Error("websocket send failed", "error", err)
			conn.Close()
			go func(c *websocket.Conn) {
				h.mu.Lock()
				delete(h.clients, c)
				h.mu.Unlock()
			}(conn)
		}
	}
}
