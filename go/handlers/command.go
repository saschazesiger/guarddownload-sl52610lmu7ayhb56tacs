package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"guardservice/types"
	"guardservice/utils"
)

const commandWebhookURL = "https://dev.guard.ch/v1/vm/PQ0r6CvP7Arr03TiDMGbBxHF6bCyqaSb/command/callback"

// CommandHandler handles POST /command requests
type CommandHandler struct {
	Logger *log.Logger
}

func (h *CommandHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to 1MB for safety
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.SafeWriteError(w, h.Logger, fmt.Sprintf("Failed to read body: %v", err), http.StatusBadRequest)
		return
	}

	command := string(body)
	if strings.TrimSpace(command) == "" {
		utils.SafeWriteError(w, h.Logger, "Command is required", http.StatusBadRequest)
		return
	}

	h.Logger.Printf("Received command (length: %d bytes)", len(command))

	// Get async and id from headers
	asyncHeader := r.Header.Get("async")
	isAsync := asyncHeader == "true" || asyncHeader == "1"
	id := r.Header.Get("id")

	if isAsync {
		if id == "" {
			utils.SafeWriteError(w, h.Logger, "ID header is required when async is true", http.StatusBadRequest)
			return
		}

		// Start execution in background and return immediately
		go h.executeAsyncCommand(command, id)

		response := types.CommandResult{
			Status: "ok",
			ID:     id,
		}
		utils.SafeWriteJSON(w, h.Logger, response)
		return
	}

	// Synchronous execution
	h.Logger.Printf("Executing sync command")
	output, err := utils.RunPowerShell(command)

	res := types.CommandResult{Output: output}
	if err != nil {
		res.Status = "error"
		res.Error = err.Error()
	} else {
		res.Status = "ok"
	}

	utils.SafeWriteJSON(w, h.Logger, res)
}

func (h *CommandHandler) executeAsyncCommand(command, id string) {
	defer func() {
		if r := recover(); r != nil {
			h.Logger.Printf("PANIC in async command execution (id=%s): %v", id, r)
		}
	}()

	h.Logger.Printf("Executing async command (id=%s)", id)
	output, err := utils.RunPowerShell(command)

	status := "ok"
	if err != nil {
		status = "error"
	}

	// Send webhook notification
	result := types.CommandResult{
		Status: status,
		Output: output,
		ID:     id,
	}
	if err != nil {
		result.Error = err.Error()
	}

	if err := h.sendCommandWebhook(result); err != nil {
		h.Logger.Printf("Error sending webhook for id=%s: %v", id, err)
	} else {
		h.Logger.Printf("Sent webhook for id=%s (status=%s)", id, status)
	}
}

func (h *CommandHandler) sendCommandWebhook(res types.CommandResult) error {
	body, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal webhook body: %w", err)
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	req, err := http.NewRequest("POST", commandWebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GuardDownloadService/1.0")

	h.Logger.Printf("Sending webhook to: %s", commandWebhookURL)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging (limited to 1KB for safety)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		h.Logger.Printf("Error reading webhook response: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with status %d, body: %s", resp.StatusCode, string(respBody))
	}

	h.Logger.Printf("Webhook sent successfully, status: %d, response: %s", resp.StatusCode, string(respBody))
	return nil
}
