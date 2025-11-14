package types

// NodeStatusRequest represents the payload for node status updates
type NodeStatusRequest struct {
	Key      string `json:"key"`
	MAC      string `json:"mac"`
	VMStatus string `json:"vmstatus"`
}

// CommandResult is used for command responses and webhooks
type CommandResult struct {
	Status string `json:"status"`
	Output string `json:"output,omitempty"`
	ID     string `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
}

// FileInfo represents a file or folder in the transfer directory
type FileInfo struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

// UploadResponse represents the response for file upload
type UploadResponse struct {
	Status   string `json:"status"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

// URLResponse represents the response for URL opening
type URLResponse struct {
	Status string `json:"status"`
	URL    string `json:"url"`
}
