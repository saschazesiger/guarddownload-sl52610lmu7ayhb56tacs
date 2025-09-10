# Guard Service - Enhanced with Web Server

This Go application provides a Windows service that combines periodic status reporting with a built-in web server for status monitoring.

## Features

### 1. Windows Service
- Runs as a Windows service with SYSTEM privileges
- Automatic startup on system boot
- Automatic restart on failure
- Proper Windows Event Log integration

### 2. Periodic Status Reporting
- Sends node status to remote API every 5 minutes
- Initial status report on service startup
- Includes MAC address and browser status
- Automatic retry on network failures

### 3. Built-in Web Server (Port 60000)
- **GET /status** - Returns the same JSON data that's sent to the remote API
- **GET /health** - Returns `{ "status": "ok", "mac": "<internal-mac>" }`
- **POST /command** - Executes a PowerShell command (supports async)
- **GET /** - Returns service information and available endpoints
- Lightweight HTTP server for local monitoring
- JSON responses for easy integration

## API Endpoints

### GET /status
Returns current node status:
```json
{
  "key": "66WyLA9sm1vBlari46KYgfQdpOdi6QHjUQ1z7MZ8LwclLEdkoV",
  "mac": "00:11:22:33:44:55",
  "browserstatus": "ready"
}
```

### GET /
Returns service information:
```json
{
  "service": "GuardDownloadService",
  "version": "1.0",
  "status": "running",
  "mac": "00:11:22:33:44:55",
  "endpoints": {
    "status": "/status",
    "health": "/health",
    "command": "/command"
  },
  "description": "Guard.ch monitoring service"
}
```

### GET /health
Returns a minimal health JSON:
```json
{
  "status": "ok",
  "mac": "00:11:22:33:44:55"
}
```

### POST /command
Accepts JSON body to execute a PowerShell command:
```json
{
  "command": "Get-Process | Select-Object -First 1",
  "async": false,
  "id": "optional-uuid-when-async",
  "context": "admin | user"
}
```

- When `async` is `true`, `id` is required. The endpoint immediately returns:
```json
{ "status": "ok", "id": "<provided-id>" }
```
and, after execution finishes, posts a webhook to
`https://dev1.srv.browser.lol/v7/workpsace/PQ0r6CvP7Arr03TiDMGbBxHF6bCyqaSb` with:
```json
{ "status": "ok" | "error", "output": "<combined stdout/stderr>", "id": "<provided-id>" }
```

- When `async` is `false`, the endpoint waits for completion and returns:
```json
{ "status": "ok" | "error", "output": "<combined stdout/stderr>" }
```

#### Context execution
- `context: "admin"` (default): Runs the command as the service account (SYSTEM) in a non-interactive session via PowerShell. Stdout/stderr is captured and returned.
- `context: "user"`: Runs the command in the currently logged-on interactive user session (GUI). This is intended for commands that need desktop access (e.g., launching Edge). Output capture is not supported in this mode; synchronous calls return `"output": "started in user session"` on success.

## Configuration

- **Service Name**: `GuardDownloadService`
- **Web Server Port**: `60000`
- **Remote API**: `https://dev1.srv.browser.lol/v7/system/nodestatus`
- **Reporting Interval**: 5 minutes

## Installation

The service is automatically installed and configured by the PowerShell script (`install.ps1`):

1. Downloads latest `guardsrv.exe` from GitHub
2. Creates Windows service with SYSTEM privileges
3. Configures Windows Firewall for port 60000
4. Sets automatic startup and failure recovery
5. Starts the service immediately

## Monitoring

You can monitor the service locally by accessing:
- `http://localhost:60000/` - Service information
- `http://localhost:60000/status` - Current node status

The service also logs to Windows Event Log for troubleshooting.

## Building

To build the executable:
```bash
env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../guardsrv.exe main.go
```

Note: This must be built for Windows (GOOS=windows) as it uses Windows-specific service APIs.
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../guardsrv.exe ./main.go
