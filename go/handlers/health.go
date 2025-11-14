package handlers

import (
	"log"
	"net/http"

	"guardservice/utils"
)

// HealthHandler handles GET /health requests
type HealthHandler struct {
	Logger  *log.Logger
	MacAddr string
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status": "ok",
		"mac":    h.MacAddr,
	}

	utils.SafeWriteJSON(w, h.Logger, response)
}
