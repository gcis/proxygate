package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/api"
	"github.com/gorilla/websocket"
)

func TestNewWSHub_NotNil(t *testing.T) {
	hub := api.NewWSHub(hSilentLogger())
	if hub == nil {
		t.Error("NewWSHub returned nil")
	}
}

func TestBroadcast_NoClients_DoesNotPanic(t *testing.T) {
	hub := api.NewWSHub(hSilentLogger())
	// Should not panic when there are no clients
	hub.Broadcast(api.WSMessage{Type: "test", Payload: "hello"})
}

func TestBroadcast_MultipleMessages_NoClients_DoesNotPanic(t *testing.T) {
	hub := api.NewWSHub(hSilentLogger())
	for i := 0; i < 10; i++ {
		hub.Broadcast(api.WSMessage{Type: "update", Payload: i})
	}
}

func TestHandleWS_WithoutUpgradeHeaders_Returns400(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	// Without WebSocket upgrade headers, the upgrader will return 400
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for non-websocket upgrade, got %d", w.Code)
	}
}

func TestHandleWS_RejectsCrossOriginUpgrade(t *testing.T) {
	hub := api.NewWSHub(hSilentLogger())
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	hdr := http.Header{"Origin": []string{"https://evil.example"}}
	if conn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr); err == nil {
		conn.Close()
		t.Fatal("cross-origin WebSocket upgrade must be rejected")
	}

	hdr = http.Header{"Origin": []string{srv.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("same-origin upgrade should succeed: %v", err)
	}
	conn.Close()
}
