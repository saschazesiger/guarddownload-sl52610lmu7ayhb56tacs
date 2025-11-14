package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"guardservice/types"
	"guardservice/utils"
)

// UploadHandler handles POST /upload requests - uploads files to Transfer folder
type UploadHandler struct {
	Logger *log.Logger
}

func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to 1GB + some overhead
	maxSize := utils.GetMaxFileSize() + 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

	err := r.ParseMultipartForm(32 << 20) // 32MB max memory
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error parsing upload: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Missing or invalid 'file' field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Check file size
	if header.Size > utils.GetMaxFileSize() {
		utils.SafeWriteError(w, h.Logger, fmt.Sprintf("File size exceeds 1GB limit (size: %d bytes)", header.Size), http.StatusRequestEntityTooLarge)
		return
	}

	transferPath, err := utils.GetTransferFolder()
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error getting transfer folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Sanitize filename
	filename := filepath.Base(header.Filename)
	if filename == "" || filename == "." || filename == ".." {
		utils.SafeWriteError(w, h.Logger, "Invalid filename", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(transferPath, filename)

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error saving file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	// Copy uploaded file to destination
	written, err := io.Copy(destFile, file)
	if err != nil {
		h.Logger.Printf("Error writing file: %v", err)
		os.Remove(destPath) // Clean up partial file
		utils.SafeWriteError(w, h.Logger, "Error saving file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.Logger.Printf("File uploaded: %s (%d bytes)", filename, written)

	response := types.UploadResponse{
		Status:   "ok",
		Filename: filename,
		Size:     written,
	}
	utils.SafeWriteJSON(w, h.Logger, response)
}
