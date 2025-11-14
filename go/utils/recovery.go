package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
)

// RecoveryMiddleware wraps HTTP handlers with panic recovery
func RecoveryMiddleware(logger *log.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic with stack trace
				logger.Printf("PANIC RECOVERED: %v\n%s", err, debug.Stack())

				// Return error response to client
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				response := map[string]interface{}{
					"status": "error",
					"error":  fmt.Sprintf("Internal server error: %v", err),
				}

				if err := json.NewEncoder(w).Encode(response); err != nil {
					logger.Printf("Error encoding panic response: %v", err)
				}
			}
		}()

		// Call the actual handler
		next(w, r)
	}
}

// SafeWriteJSON safely writes JSON response with error handling
func SafeWriteJSON(w http.ResponseWriter, logger *log.Logger, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

// SafeWriteError safely writes error response
func SafeWriteError(w http.ResponseWriter, logger *log.Logger, message string, statusCode int) {
	logger.Printf("HTTP Error %d: %s", statusCode, message)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"status": "error",
		"error":  message,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Printf("Error encoding error response: %v", err)
	}
}
