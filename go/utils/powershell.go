package utils

import (
	"fmt"
	"os/exec"
	"strings"
)

// RunPowerShell executes a PowerShell command and returns its combined output
func RunPowerShell(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("command cannot be empty")
	}

	// Prefer powershell.exe since this service targets Windows
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)

	// Capture combined stdout/stderr
	out, err := cmd.CombinedOutput()
	return string(out), err
}
