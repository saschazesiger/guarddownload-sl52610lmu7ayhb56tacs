package handlers

import (
	"log"
	"net/http"

	"guardservice/utils"
)

// RootHandler provides basic service information
type RootHandler struct {
	Logger     *log.Logger
	ServiceName string
	MacAddr    string
}

func (h *RootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	info := map[string]interface{}{
		"service": h.ServiceName,
		"version": "1.0",
		"status":  "running",
		"mac":     h.MacAddr,
		"endpoints": map[string]string{
			"status":   "/status",
			"health":   "/health",
			"command":  "/command",
			"file":     "/file",
			"download": "/download",
			"upload":   "/upload",
			"url":      "/url",
		},
		"description": "Guard.ch monitoring service",
	}

	utils.SafeWriteJSON(w, h.Logger, info)
}
