package handlers

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"guardservice/utils"
)

// DownloadHandler handles GET /download requests - downloads files or zipped folders
type DownloadHandler struct {
	Logger *log.Logger
}

func (h *DownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Query().Get("file")
	if filename == "" {
		utils.SafeWriteError(w, h.Logger, "Missing 'file' query parameter", http.StatusBadRequest)
		return
	}

	transferPath, err := utils.GetTransferFolder()
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error getting transfer folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	filePath, err := utils.ValidatePath(transferPath, filename)
	if err != nil {
		utils.SafeWriteError(w, h.Logger, err.Error(), http.StatusBadRequest)
		return
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			utils.SafeWriteError(w, h.Logger, "File not found", http.StatusNotFound)
		} else {
			utils.SafeWriteError(w, h.Logger, "Error accessing file: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if fileInfo.IsDir() {
		h.downloadFolderAsZip(w, filePath, filename)
	} else {
		h.downloadFile(w, filePath, filename, fileInfo.Size())
	}
}

func (h *DownloadHandler) downloadFolderAsZip(w http.ResponseWriter, folderPath, folderName string) {
	// Check total folder size before zipping
	totalSize, err := utils.CalculateFolderSize(folderPath)
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error calculating folder size: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if totalSize > utils.GetMaxFileSize() {
		utils.SafeWriteError(w, h.Logger, fmt.Sprintf("Folder size exceeds 1GB limit (size: %d bytes)", totalSize), http.StatusRequestEntityTooLarge)
		return
	}

	// Set headers
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zip\"", folderName))

	zipWriter := zip.NewWriter(w)
	defer func() {
		if err := zipWriter.Close(); err != nil {
			h.Logger.Printf("Error closing zip writer: %v", err)
		}
	}()

	err = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(folderPath, path)
		if err != nil {
			return err
		}

		// Create zip header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.Join(folderName, relPath)
		header.Method = zip.Deflate

		if info.IsDir() {
			header.Name += "/"
			_, err = zipWriter.CreateHeader(header)
			return err
		}

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		h.Logger.Printf("Error creating zip: %v", err)
		return
	}

	h.Logger.Printf("Downloaded folder as zip: %s (total size: %d bytes)", folderName, totalSize)
}

func (h *DownloadHandler) downloadFile(w http.ResponseWriter, filePath, filename string, fileSize int64) {
	// Check file size
	if fileSize > utils.GetMaxFileSize() {
		utils.SafeWriteError(w, h.Logger, fmt.Sprintf("File size exceeds 1GB limit (size: %d bytes)", fileSize), http.StatusRequestEntityTooLarge)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))

	file, err := os.Open(filePath)
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error opening file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	_, err = io.Copy(w, file)
	if err != nil {
		h.Logger.Printf("Error sending file: %v", err)
		return
	}

	h.Logger.Printf("Downloaded file: %s (%d bytes)", filename, fileSize)
}
