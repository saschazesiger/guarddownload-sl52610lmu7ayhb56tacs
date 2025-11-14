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
	"os/signal"
	"syscall"
	"time"

	"guardservice/handlers"
	"guardservice/types"
	"guardservice/utils"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	serviceName   = "GuardDownloadService"
	apiURL        = "https://dev.guard.ch/v1/vm/PQ0r6CvP7Arr03TiDMGbBxHF6bCyqaSb"
	apiKey        = "66WyLA9sm1vBlari46KYgfQdpOdi6QHjUQ1z7MZ8LwclLEdkoV"
	webServerPort = ":60000"
)

type service struct {
	logger     *log.Logger
	httpServer *http.Server
	macAddr    string
	statusData *types.NodeStatusRequest
}

func (s *service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Start the main service logic in a goroutine
	done := make(chan bool)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Printf("PANIC in service.run: %v", r)
			}
			done <- true
		}()
		s.run()
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
	s.statusData = &types.NodeStatusRequest{
		Key:      apiKey,
		MAC:      macAddr,
		VMStatus: "ready",
	}

	// Setup HTTP server with handlers
	mux := http.NewServeMux()

	// Create handlers
	statusHandler := &handlers.StatusHandler{
		Logger:     s.logger,
		StatusData: s.statusData,
	}
	healthHandler := &handlers.HealthHandler{
		Logger:  s.logger,
		MacAddr: s.macAddr,
	}
	commandHandler := &handlers.CommandHandler{
		Logger: s.logger,
	}
	fileHandler := &handlers.FileHandler{
		Logger: s.logger,
	}
	downloadHandler := &handlers.DownloadHandler{
		Logger: s.logger,
	}
	uploadHandler := &handlers.UploadHandler{
		Logger: s.logger,
	}
	urlHandler := &handlers.URLHandler{
		Logger: s.logger,
	}
	rootHandler := &handlers.RootHandler{
		Logger:      s.logger,
		ServiceName: serviceName,
		MacAddr:     s.macAddr,
	}

	// Register handlers with recovery middleware
	mux.HandleFunc("/status", utils.RecoveryMiddleware(s.logger, statusHandler.ServeHTTP))
	mux.HandleFunc("/health", utils.RecoveryMiddleware(s.logger, healthHandler.ServeHTTP))
	mux.HandleFunc("/command", utils.RecoveryMiddleware(s.logger, commandHandler.ServeHTTP))
	mux.HandleFunc("/file", utils.RecoveryMiddleware(s.logger, fileHandler.ServeHTTP))
	mux.HandleFunc("/download", utils.RecoveryMiddleware(s.logger, downloadHandler.ServeHTTP))
	mux.HandleFunc("/upload", utils.RecoveryMiddleware(s.logger, uploadHandler.ServeHTTP))
	mux.HandleFunc("/url", utils.RecoveryMiddleware(s.logger, urlHandler.ServeHTTP))
	mux.HandleFunc("/", utils.RecoveryMiddleware(s.logger, rootHandler.ServeHTTP))

	s.httpServer = &http.Server{
		Addr:    webServerPort,
		Handler: mux,
	}

	// Start web server in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Printf("PANIC in web server: %v", r)
			}
		}()

		s.logger.Printf("Starting web server on port %s", webServerPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Printf("Web server error: %v", err)
		}
	}()

	// Start periodic status reporting in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Printf("PANIC in status reporting: %v", r)
			}
		}()

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

func (s *service) sendNodeStatus(request types.NodeStatusRequest) bool {
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
