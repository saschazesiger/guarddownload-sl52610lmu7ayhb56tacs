package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"guardservice/types"
	"guardservice/utils"
)

// URLHandler handles POST /url requests - opens URLs in Edge browser
type URLHandler struct {
	Logger *log.Logger
}

func (h *URLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SafeWriteError(w, h.Logger, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read URL from request body
	body, err := io.ReadAll(io.LimitReader(r.Body, 2048))
	if err != nil {
		utils.SafeWriteError(w, h.Logger, "Error reading request: "+err.Error(), http.StatusBadRequest)
		return
	}

	url := strings.TrimSpace(string(body))
	if url == "" {
		utils.SafeWriteError(w, h.Logger, "URL is required", http.StatusBadRequest)
		return
	}

	// Validate URL format (basic check)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		utils.SafeWriteError(w, h.Logger, "URL must start with http:// or https://", http.StatusBadRequest)
		return
	}

	h.Logger.Printf("Opening URL in Edge: %s", url)

	// Create a scheduled task to open Edge in the user's desktop session
	taskName := fmt.Sprintf("GuardOpenURL_%d", time.Now().Unix())

	// PowerShell script to create and run task
	psScript := fmt.Sprintf(`
		$taskName = "%s"
		$url = "%s"

		try {
			# Get the current logged-in user
			$username = (Get-WmiObject -Class Win32_ComputerSystem).UserName
			if ($username -match "\\") {
				$username = $username.Split("\")[1]
			}

			# Create task action to open Edge
			$action = New-ScheduledTaskAction -Execute "msedge.exe" -Argument "$url"

			# Create task principal to run as the logged-in user
			$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$username" -LogonType Interactive

			# Create task settings
			$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

			# Register the task
			Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null

			# Start the task immediately
			Start-ScheduledTask -TaskName $taskName

			# Wait a moment for the task to start
			Start-Sleep -Seconds 2

			# Clean up the task
			Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

			Write-Output "SUCCESS"
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, taskName, url)

	// Execute the PowerShell script
	output, err := utils.RunPowerShell(psScript)
	if err != nil {
		h.Logger.Printf("Error opening URL: %v, output: %s", err, output)
		utils.SafeWriteError(w, h.Logger, fmt.Sprintf("Error opening URL: %v", err), http.StatusInternalServerError)
		return
	}

	h.Logger.Printf("URL opened successfully: %s", url)

	response := types.URLResponse{
		Status: "ok",
		URL:    url,
	}
	utils.SafeWriteJSON(w, h.Logger, response)
}
