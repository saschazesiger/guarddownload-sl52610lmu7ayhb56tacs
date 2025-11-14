package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxFileSize = 1 << 30 // 1GB in bytes

// GetTransferFolder returns the path to the Transfer folder on Desktop
// Creates the folder if it doesn't exist
func GetTransferFolder() (string, error) {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return "", fmt.Errorf("USERPROFILE environment variable not set")
	}

	transferPath := filepath.Join(userProfile, "Desktop", "Transfer")

	// Create the folder if it doesn't exist
	if err := os.MkdirAll(transferPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create transfer folder: %w", err)
	}

	return transferPath, nil
}

// ValidatePath ensures the file path is within the transfer folder
// Returns an error if path traversal is detected
func ValidatePath(transferPath, filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("filename cannot be empty")
	}

	filePath := filepath.Join(transferPath, filename)

	// Security check: ensure the file is within the transfer folder
	cleanFilePath := filepath.Clean(filePath)
	cleanTransferPath := filepath.Clean(transferPath)

	if !strings.HasPrefix(cleanFilePath, cleanTransferPath) {
		return "", fmt.Errorf("invalid file path: path traversal detected")
	}

	return filePath, nil
}

// GetMaxFileSize returns the maximum allowed file size
func GetMaxFileSize() int64 {
	return maxFileSize
}

// CalculateFolderSize calculates the total size of all files in a folder
func CalculateFolderSize(folderPath string) (int64, error) {
	var totalSize int64

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to calculate folder size: %w", err)
	}

	return totalSize, nil
}
