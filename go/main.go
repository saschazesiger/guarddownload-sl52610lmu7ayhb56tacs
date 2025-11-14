package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows/svc"
)

func main() {
	// Recover from any panics in main
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in main: %v", r)
			os.Exit(1)
		}
	}()

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
