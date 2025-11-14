package handlers

import (
	"log"
	"net/http"
	"os"
	"time"

	"guardservice/types"
	"guardservice/utils"
)

// FileHandler handles GET /file requests - lists files in Transfer folder
type FileHandler struct {
	Logger *log.Logger
}

func (h *FileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	transferPath, err := utils.GetTransferFolder()
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error getting transfer folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	entries, err := os.ReadDir(transferPath)
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error reading transfer folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	files := make([]types.FileInfo, 0, len(entries))
	for _, entry := range entries {
		// Skip desktop.ini
		if entry.Name() == "desktop.ini" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			h.Logger.Printf("Error getting file info for %s: %v", entry.Name(), err)
			continue
		}

		files = append(files, types.FileInfo{
			Name:    entry.Name(),
			IsDir:   entry.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}

	utils.SafeWriteJSON(w, h.Logger, files)
	h.Logger.Printf("File list served: %d items", len(files))
}
