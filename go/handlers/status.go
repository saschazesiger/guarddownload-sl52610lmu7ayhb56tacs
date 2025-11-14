package handlers

import (
	"log"
	"net/http"

	"guardservice/types"
	"guardservice/utils"
)

// StatusHandler handles GET /status requests
type StatusHandler struct {
	Logger     *log.Logger
	StatusData *types.NodeStatusRequest
}

func (h *StatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.StatusData == nil {
		utils.SafeWriteError(w, h.Logger, "Status data not available", http.StatusInternalServerError)
		return
	}

	utils.SafeWriteJSON(w, h.Logger, h.StatusData)
	h.Logger.Printf("Status request served for MAC: %s", h.StatusData.MAC)
}
