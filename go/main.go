package main

import (
    "archive/zip"
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "strings"
    "syscall"
    "time"

    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/debug"
    "golang.org/x/sys/windows/svc/eventlog"
)

const (
    serviceName = "GuardDownloadService"
    apiURL      = "https://dev.guard.ch/v1/vm/PQ0r6CvP7Arr03TiDMGbBxHF6bCyqaSb"
    apiKey      = "66WyLA9sm1vBlari46KYgfQdpOdi6QHjUQ1z7MZ8LwclLEdkoV"
    webServerPort = ":60000"
    maxFileSize   = 1 << 30 // 1GB in bytes
)

// webhook for async command completion notifications
const commandWebhookURL = "https://dev.guard.ch/v1/vm/PQ0r6CvP7Arr03TiDMGbBxHF6bCyqaSb/command/callback"

type NodeStatusRequest struct {
	Key      string `json:"key"`
	MAC      string `json:"mac"`
	VMStatus string `json:"vmstatus"`
}

type service struct {
    logger     *log.Logger
    httpServer *http.Server
    macAddr    string
    statusData *NodeStatusRequest
}

// CommandRequest defines the payload for /command
// Note: Command is now read from request body directly, async and id from headers

// CommandResult is used for responses and webhooks
type CommandResult struct {
    Status string `json:"status"`
    Output string `json:"output,omitempty"`
    ID     string `json:"id,omitempty"`
    Error  string `json:"error,omitempty"`
}

func main() {
	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
	}
	if !isIntSess {
		runService(serviceName, false)
		return
	}

	// Running interactively (for testing)
	fmt.Println("Running in interactive mode...")
	s := &service{logger: log.New(os.Stdout, "", log.LstdFlags)}
	s.run()
}

func (s *service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Start the main service logic in a goroutine
	done := make(chan bool)
	go func() {
		s.run()
		done <- true
	}()

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.logger.Println("Service stopping...")
				// Shutdown web server gracefully
				if s.httpServer != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := s.httpServer.Shutdown(ctx); err != nil {
						s.logger.Printf("Web server shutdown error: %v", err)
					}
				}
				break loop
			default:
				s.logger.Printf("Unexpected control request #%d", c)
			}
		case <-done:
			break loop
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func (s *service) run() {
	// Get MAC address once at startup
	macAddr, err := getMACAddress()
	if err != nil {
		s.logger.Printf("Error getting MAC address: %v", err)
		return
	}
	
	s.macAddr = macAddr
	s.logger.Printf("Starting service with MAC address: %s", macAddr)

	// Create status data
	s.statusData = &NodeStatusRequest{
		Key:      apiKey,
		MAC:      macAddr,
		VMStatus: "ready",
	}

    // Setup HTTP server
    mux := http.NewServeMux()
    mux.HandleFunc("/status", s.handleStatus)
    mux.HandleFunc("/health", s.handleHealth)
    mux.HandleFunc("/command", s.handleCommand)
    mux.HandleFunc("/file", s.handleFile)
    mux.HandleFunc("/download", s.handleDownload)
    mux.HandleFunc("/upload", s.handleUpload)
    mux.HandleFunc("/url", s.handleURL)
    mux.HandleFunc("/", s.handleRoot) // Default handler
	
	s.httpServer = &http.Server{
		Addr:    webServerPort,
		Handler: mux,
	}

	// Start web server in a goroutine
	go func() {
		s.logger.Printf("Starting web server on port %s", webServerPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Printf("Web server error: %v", err)
		}
	}()

	// Start periodic status reporting in a goroutine
	go func() {
		s.logger.Println("Starting periodic status reporting...")
		
		// Initial status report - keep trying until successful
		for {
			if s.sendNodeStatus(*s.statusData) {
				s.logger.Println("Successfully sent initial node status - stopping periodic reports")
				return // Stop after successful send
			}
			s.logger.Println("Failed to send initial node status, retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}()

	// Keep the service running
	s.logger.Println("Service running... Press Ctrl+C to stop (in interactive mode)")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	
	// Shutdown web server gracefully
	s.logger.Println("Shutting down web server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Printf("Web server shutdown error: %v", err)
	}
	
	s.logger.Println("Service stopped")
}

// HTTP handler for GET /status
func (s *service) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set content type to JSON
	w.Header().Set("Content-Type", "application/json")
	
	// Return the same data that we send via POST
	if err := json.NewEncoder(w).Encode(s.statusData); err != nil {
		s.logger.Printf("Error encoding status response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	s.logger.Printf("Status request served for MAC: %s", s.macAddr)
}

// HTTP handler for GET /health
func (s *service) handleHealth(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    resp := map[string]interface{}{
        "status": "ok",
        "mac":    s.macAddr,
    }
    if err := json.NewEncoder(w).Encode(resp); err != nil {
        s.logger.Printf("Error encoding health response: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
}

// HTTP handler for POST /command
func (s *service) handleCommand(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        s.logger.Printf("Command request with invalid method: %s", r.Method)
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Limit request body size to 1MB for safety
    r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

    // Read body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        s.logger.Printf("Error reading command body: %v", err)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(CommandResult{Status: "error", Error: fmt.Sprintf("failed to read body: %v", err)})
        return
    }

    command := string(body)
    if strings.TrimSpace(command) == "" {
        s.logger.Printf("Empty command received")
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(CommandResult{Status: "error", Error: "command is required"})
        return
    }

    s.logger.Printf("Received command (length: %d bytes)", len(command))

    // Get async and id from headers
    asyncHeader := r.Header.Get("async")
    isAsync := asyncHeader == "true" || asyncHeader == "1"
    id := r.Header.Get("id")

    if isAsync {
        if id == "" {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusBadRequest)
            _ = json.NewEncoder(w).Encode(CommandResult{Status: "error", Error: "id header is required when async is true"})
            return
        }

        // Start execution in background and return immediately
        go func() {
            s.logger.Printf("Executing async command (id=%s)", id)
            output, err := runPowerShell(command)
            status := "ok"
            if err != nil {
                status = "error"
            }
            // Send webhook notification
            result := CommandResult{Status: status, Output: output, ID: id}
            if err != nil {
                result.Error = err.Error()
            }
            if err2 := s.sendCommandWebhook(result); err2 != nil {
                s.logger.Printf("Error sending webhook for id=%s: %v", id, err2)
            } else {
                s.logger.Printf("Sent webhook for id=%s (status=%s)", id, status)
            }
        }()

        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(CommandResult{Status: "ok", ID: id})
        return
    }

    // Synchronous execution
    s.logger.Printf("Executing sync command")
    output, err := runPowerShell(command)
    res := CommandResult{Output: output}
    if err != nil {
        res.Status = "error"
        res.Error = err.Error()
    } else {
        res.Status = "ok"
    }

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(res)
}

// HTTP handler for root path - provides basic info
func (s *service) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

    info := map[string]interface{}{
        "service": serviceName,
        "version": "1.0",
        "status":  "running",
        "mac":     s.macAddr,
        "endpoints": map[string]string{
            "status": "/status",
            "health": "/health",
            "command": "/command",
            "file": "/file",
            "download": "/download",
            "upload": "/upload",
            "url": "/url",
        },
        "description": "Guard.ch monitoring service",
    }

	if err := json.NewEncoder(w).Encode(info); err != nil {
		s.logger.Printf("Error encoding root response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// getTransferFolder returns the path to the Transfer folder on Desktop
func getTransferFolder() (string, error) {
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

// FileInfo represents a file or folder in the transfer directory
type FileInfo struct {
    Name    string `json:"name"`
    IsDir   bool   `json:"is_dir"`
    Size    int64  `json:"size"`
    ModTime string `json:"mod_time"`
}

// HTTP handler for GET /file - lists all files in Transfer folder
func (s *service) handleFile(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    transferPath, err := getTransferFolder()
    if err != nil {
        s.logger.Printf("Error getting transfer folder: %v", err)
        http.Error(w, fmt.Sprintf("Error getting transfer folder: %v", err), http.StatusInternalServerError)
        return
    }

    entries, err := os.ReadDir(transferPath)
    if err != nil {
        s.logger.Printf("Error reading transfer folder: %v", err)
        http.Error(w, fmt.Sprintf("Error reading transfer folder: %v", err), http.StatusInternalServerError)
        return
    }

    files := make([]FileInfo, 0)
    for _, entry := range entries {
        // Skip desktop.ini
        if entry.Name() == "desktop.ini" {
            continue
        }

        info, err := entry.Info()
        if err != nil {
            s.logger.Printf("Error getting file info for %s: %v", entry.Name(), err)
            continue
        }

        files = append(files, FileInfo{
            Name:    entry.Name(),
            IsDir:   entry.IsDir(),
            Size:    info.Size(),
            ModTime: info.ModTime().Format(time.RFC3339),
        })
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(files); err != nil {
        s.logger.Printf("Error encoding file list: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    s.logger.Printf("File list served: %d items", len(files))
}

// HTTP handler for GET /download - downloads a file or zipped folder
func (s *service) handleDownload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    filename := r.URL.Query().Get("file")
    if filename == "" {
        http.Error(w, "Missing 'file' query parameter", http.StatusBadRequest)
        return
    }

    transferPath, err := getTransferFolder()
    if err != nil {
        s.logger.Printf("Error getting transfer folder: %v", err)
        http.Error(w, fmt.Sprintf("Error getting transfer folder: %v", err), http.StatusInternalServerError)
        return
    }

    filePath := filepath.Join(transferPath, filename)

    // Security check: ensure the file is within the transfer folder
    if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(transferPath)) {
        s.logger.Printf("Security violation: attempt to access file outside transfer folder: %s", filename)
        http.Error(w, "Invalid file path", http.StatusBadRequest)
        return
    }

    fileInfo, err := os.Stat(filePath)
    if err != nil {
        s.logger.Printf("Error accessing file %s: %v", filename, err)
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }

    if fileInfo.IsDir() {
        // Check total folder size before zipping
        var totalSize int64
        err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            if !info.IsDir() {
                totalSize += info.Size()
            }
            return nil
        })
        if err != nil {
            s.logger.Printf("Error calculating folder size: %v", err)
            http.Error(w, "Error calculating folder size", http.StatusInternalServerError)
            return
        }

        if totalSize > maxFileSize {
            s.logger.Printf("Folder too large: %d bytes (max: %d)", totalSize, maxFileSize)
            http.Error(w, fmt.Sprintf("Folder size exceeds 1GB limit (size: %d bytes)", totalSize), http.StatusRequestEntityTooLarge)
            return
        }

        // Create ZIP file in memory
        w.Header().Set("Content-Type", "application/zip")
        w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zip\"", filename))

        zipWriter := zip.NewWriter(w)
        defer zipWriter.Close()

        err = filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }

            // Get relative path
            relPath, err := filepath.Rel(filePath, path)
            if err != nil {
                return err
            }

            // Create zip header
            header, err := zip.FileInfoHeader(info)
            if err != nil {
                return err
            }
            header.Name = filepath.Join(filename, relPath)
            header.Method = zip.Deflate

            if info.IsDir() {
                header.Name += "/"
            } else {
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
                if err != nil {
                    return err
                }
            }

            return nil
        })

        if err != nil {
            s.logger.Printf("Error creating zip: %v", err)
            return
        }

        s.logger.Printf("Downloaded folder as zip: %s (total size: %d bytes)", filename, totalSize)
    } else {
        // Regular file download
        if fileInfo.Size() > maxFileSize {
            s.logger.Printf("File too large: %d bytes (max: %d)", fileInfo.Size(), maxFileSize)
            http.Error(w, fmt.Sprintf("File size exceeds 1GB limit (size: %d bytes)", fileInfo.Size()), http.StatusRequestEntityTooLarge)
            return
        }

        w.Header().Set("Content-Type", "application/octet-stream")
        w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
        w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

        file, err := os.Open(filePath)
        if err != nil {
            s.logger.Printf("Error opening file: %v", err)
            http.Error(w, "Error opening file", http.StatusInternalServerError)
            return
        }
        defer file.Close()

        _, err = io.Copy(w, file)
        if err != nil {
            s.logger.Printf("Error sending file: %v", err)
            return
        }

        s.logger.Printf("Downloaded file: %s (%d bytes)", filename, fileInfo.Size())
    }
}

// HTTP handler for POST /upload - uploads a file to Transfer folder
func (s *service) handleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Limit request body size to 1GB + some overhead
    r.Body = http.MaxBytesReader(w, r.Body, maxFileSize+1024)

    err := r.ParseMultipartForm(32 << 20) // 32MB max memory
    if err != nil {
        s.logger.Printf("Error parsing multipart form: %v", err)
        http.Error(w, fmt.Sprintf("Error parsing upload: %v", err), http.StatusBadRequest)
        return
    }

    file, header, err := r.FormFile("file")
    if err != nil {
        s.logger.Printf("Error getting uploaded file: %v", err)
        http.Error(w, "Missing or invalid 'file' field", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Check file size
    if header.Size > maxFileSize {
        s.logger.Printf("Uploaded file too large: %d bytes (max: %d)", header.Size, maxFileSize)
        http.Error(w, fmt.Sprintf("File size exceeds 1GB limit (size: %d bytes)", header.Size), http.StatusRequestEntityTooLarge)
        return
    }

    transferPath, err := getTransferFolder()
    if err != nil {
        s.logger.Printf("Error getting transfer folder: %v", err)
        http.Error(w, fmt.Sprintf("Error getting transfer folder: %v", err), http.StatusInternalServerError)
        return
    }

    // Sanitize filename
    filename := filepath.Base(header.Filename)
    destPath := filepath.Join(transferPath, filename)

    // Create destination file
    destFile, err := os.Create(destPath)
    if err != nil {
        s.logger.Printf("Error creating destination file: %v", err)
        http.Error(w, "Error saving file", http.StatusInternalServerError)
        return
    }
    defer destFile.Close()

    // Copy uploaded file to destination
    written, err := io.Copy(destFile, file)
    if err != nil {
        s.logger.Printf("Error writing file: %v", err)
        os.Remove(destPath) // Clean up partial file
        http.Error(w, "Error saving file", http.StatusInternalServerError)
        return
    }

    s.logger.Printf("File uploaded: %s (%d bytes)", filename, written)

    w.Header().Set("Content-Type", "application/json")
    response := map[string]interface{}{
        "status":   "ok",
        "filename": filename,
        "size":     written,
    }
    json.NewEncoder(w).Encode(response)
}

// HTTP handler for POST /url - opens a URL in Edge browser on desktop
func (s *service) handleURL(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Read URL from request body
    body, err := io.ReadAll(io.LimitReader(r.Body, 2048))
    if err != nil {
        s.logger.Printf("Error reading URL body: %v", err)
        http.Error(w, "Error reading request", http.StatusBadRequest)
        return
    }

    url := strings.TrimSpace(string(body))
    if url == "" {
        http.Error(w, "URL is required", http.StatusBadRequest)
        return
    }

    // Validate URL format (basic check)
    if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
        http.Error(w, "URL must start with http:// or https://", http.StatusBadRequest)
        return
    }

    s.logger.Printf("Opening URL in Edge: %s", url)

    // Create a scheduled task to open Edge in the user's desktop session
    taskName := fmt.Sprintf("GuardOpenURL_%d", time.Now().Unix())

    // PowerShell script to create and run task
    psScript := fmt.Sprintf(`
        $taskName = "%s"
        $url = "%s"

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
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    `, taskName, url)

    // Execute the PowerShell script
    output, err := runPowerShell(psScript)
    if err != nil {
        s.logger.Printf("Error opening URL: %v, output: %s", err, output)
        http.Error(w, fmt.Sprintf("Error opening URL: %v", err), http.StatusInternalServerError)
        return
    }

    s.logger.Printf("URL opened successfully: %s", url)

    w.Header().Set("Content-Type", "application/json")
    response := map[string]interface{}{
        "status": "ok",
        "url":    url,
    }
    json.NewEncoder(w).Encode(response)
}

func (s *service) sendNodeStatus(request NodeStatusRequest) bool {
	jsonData, err := json.Marshal(request)
	if err != nil {
		s.logger.Printf("Error marshaling JSON: %v", err)
		return false
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		s.logger.Printf("Error creating request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GuardDownloadService/1.0")

	s.logger.Printf("Sending status update to: %s", apiURL)
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Printf("Error sending request: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Read response body for logging (limited to 1KB for safety)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		s.logger.Printf("Error reading response body: %v", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.logger.Printf("Request successful, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
		return true
	}

	s.logger.Printf("Request failed with status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	return false
}

func getMACAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Skip loopback and interfaces without hardware address
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		// Check if interface is up
		if iface.Flags&net.FlagUp != 0 {
			return iface.HardwareAddr.String(), nil
		}
	}

	return "", fmt.Errorf("no active network interface found")
}

// runPowerShell executes a PowerShell command and returns its combined output
func runPowerShell(command string) (string, error) {
    // Prefer powershell.exe since this service targets Windows
    cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
    // Capture combined stdout/stderr
    out, err := cmd.CombinedOutput()
    return string(out), err
}


// sendCommandWebhook posts the command result to the configured webhook URL
func (s *service) sendCommandWebhook(res CommandResult) error {
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

    s.logger.Printf("Sending webhook to: %s", commandWebhookURL)
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("send webhook: %w", err)
    }
    defer resp.Body.Close()

    // Read response body for logging (limited to 1KB for safety)
    respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
    if err != nil {
        s.logger.Printf("Error reading webhook response: %v", err)
    }

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("webhook responded with status %d, body: %s", resp.StatusCode, string(respBody))
    }
    s.logger.Printf("Webhook sent successfully, status: %d, response: %s", resp.StatusCode, string(respBody))
    return nil
}

func runService(name string, isDebug bool) {
	var err error
	var logger *log.Logger

	if isDebug {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		logger = log.New(os.Stderr, "", log.LstdFlags)
		elog, err := eventlog.Open(name)
		if err != nil {
			logger.Printf("failed to open event log: %v", err)
			return
		}
		defer elog.Close()
		
		// Redirect log output to event log
		logger.SetOutput(&eventLogWriter{elog: elog})
	}

	s := &service{logger: logger}

	if isDebug {
		err = debug.Run(name, s)
	} else {
		err = svc.Run(name, s)
	}
	if err != nil {
		logger.Printf("service failed: %v", err)
	}
}

type eventLogWriter struct {
	elog *eventlog.Log
}

func (w *eventLogWriter) Write(p []byte) (n int, err error) {
	err = w.elog.Info(1, string(p))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
