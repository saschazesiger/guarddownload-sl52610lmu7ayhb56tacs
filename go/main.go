package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	serviceName = "GuardDownloadService"
	apiURL      = "https://dev1.srv.browser.lol/v7/system/nodestatus"
	apiKey      = "66WyLA9sm1vBlari46KYgfQdpOdi6QHjUQ1z7MZ8LwclLEdkoV"
)

type NodeStatusRequest struct {
	Key           string `json:"key"`
	MAC           string `json:"mac"`
	BrowserStatus string `json:"browserstatus"`
}

type service struct {
	logger *log.Logger
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
	// Get MAC address
	macAddr, err := getMACAddress()
	if err != nil {
		s.logger.Printf("Error getting MAC address: %v", err)
		return
	}

	s.logger.Printf("Starting service with MAC address: %s", macAddr)

	// Create request payload
	request := NodeStatusRequest{
		Key:           apiKey,
		MAC:           macAddr,
		BrowserStatus: "ready",
	}

	// Keep trying to send the request until successful
	for {
		if s.sendNodeStatus(request) {
			s.logger.Println("Successfully sent node status")
			break
		}
		s.logger.Println("Failed to send node status, retrying in 5 seconds...")
		time.Sleep(5 * time.Second)
	}

	// Keep the service running
	s.logger.Println("Service running... Press Ctrl+C to stop (in interactive mode)")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	s.logger.Println("Service stopped")
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
