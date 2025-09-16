package main

import (
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
    "strings"
    "syscall"
    "time"

    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/debug"
    "golang.org/x/sys/windows/svc/eventlog"
)

const (
    serviceName = "GuardDownloadService"
    apiURL      = "https://dev1.srv.browser.lol/v7/workspace/Lcg7Fq7Cfi1JOF5ND0zrqUL4ly949P8w"
    apiKey      = "66WyLA9sm1vBlari46KYgfQdpOdi6QHjUQ1z7MZ8LwclLEdkoV"
    webServerPort = ":60000"
)

// webhook for async command completion notifications
const commandWebhookURL = "https://dev1.srv.browser.lol/v7/workpsace/PQ0r6CvP7Arr03TiDMGbBxHF6bCyqaSb"

type NodeStatusRequest struct {
	Key           string `json:"key"`
	MAC           string `json:"mac"`
	BrowserStatus string `json:"browserstatus"`
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
		Key:           apiKey,
		MAC:           macAddr,
		BrowserStatus: "ready",
	}

    // Setup HTTP server
    mux := http.NewServeMux()
    mux.HandleFunc("/status", s.handleStatus)
    mux.HandleFunc("/health", s.handleHealth)
    mux.HandleFunc("/command", s.handleCommand)
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
				s.logger.Println("Successfully sent initial node status")
				break
			}
			s.logger.Println("Failed to send initial node status, retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		}

		// Continue with periodic reporting (every 5 minutes)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				if s.sendNodeStatus(*s.statusData) {
					s.logger.Println("Periodic status report sent successfully")
				} else {
					s.logger.Println("Failed to send periodic status report")
				}
			}
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
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Read body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(CommandResult{Status: "error", Error: fmt.Sprintf("failed to read body: %v", err)})
        return
    }

    command := string(body)
    if strings.TrimSpace(command) == "" {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(CommandResult{Status: "error", Error: "command is required"})
        return
    }

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
        },
        "description": "Guard.ch monitoring service",
    }
	
	if err := json.NewEncoder(w).Encode(info); err != nil {
		s.logger.Printf("Error encoding root response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *service) sendNodeStatus(request NodeStatusRequest) bool {
	jsonData, err := json.Marshal(request)
	if err != nil {
		s.logger.Printf("Error marshaling JSON: %v", err)
		return false
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		s.logger.Printf("Error creating request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		s.logger.Printf("Error sending request: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.logger.Printf("Request successful, status code: %d", resp.StatusCode)
		return true
	}

	s.logger.Printf("Request failed with status code: %d", resp.StatusCode)
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
    client := &http.Client{Timeout: 15 * time.Second}
    req, err := http.NewRequest("POST", commandWebhookURL, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("create webhook request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("send webhook: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("webhook responded with status %d", resp.StatusCode)
    }
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
