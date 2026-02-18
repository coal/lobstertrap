package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"time"

	"nhooyr.io/websocket"
)

//go:embed static/dashboard.html
var staticFS embed.FS

// Handler returns an http.Handler that serves the dashboard routes.
// All routes are under /_lobstertrap/.
func Handler(hub *Hub) http.Handler {
	mux := http.NewServeMux()

	// Dashboard HTML
	mux.HandleFunc("/_lobstertrap/", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/dashboard.html")
		if err != nil {
			http.Error(w, "dashboard not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// WebSocket endpoint
	mux.HandleFunc("/_lobstertrap/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // Allow connections from any origin
		})
		if err != nil {
			return
		}
		defer conn.CloseNow()

		hub.Register(conn)
		defer hub.Unregister(conn)

		// Keep the connection open by reading (and discarding) client messages.
		// The connection closes when the client disconnects or context is cancelled.
		ctx := conn.CloseRead(context.Background())
		<-ctx.Done()
	})

	// REST: stats snapshot
	mux.HandleFunc("/_lobstertrap/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hub.StatsSnapshot())
	})

	// REST: recent events
	mux.HandleFunc("/_lobstertrap/api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hub.Events().All())
	})

	// REST: policy
	mux.HandleFunc("/_lobstertrap/api/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hub.PolicyConfig())
	})

	return mux
}

// Run starts the periodic stats broadcast in background.
func Run(ctx context.Context, hub *Hub) {
	go hub.StartStatsBroadcast(ctx, 5*time.Second)
}
