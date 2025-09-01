# GuardDownload Service

A Windows service written in Go that sends periodic status updates to the browser service endpoint.

## Features

- Sends POST requests to `https://dev1.srv.browser.lol/v7/system/nodestatus`
- Automatically detects the main network adapter's MAC address
- Retries failed requests every 5 seconds until successful
- Runs as a Windows service
- Includes comprehensive logging

## Building the Application

### Prerequisites


### Build Steps

go mod tidy
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../guardsrv.exe ./main.go
