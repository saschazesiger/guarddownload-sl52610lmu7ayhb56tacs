#region Setup and initialization
# Start transcript logging with timestamp for better tracking
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Start-Transcript -Path "$env:TEMP\guard_install_$timestamp.log" -Force

# Global variable for enhanced error logging
$global:errorLog = @()

# Function for better error logs
function Write-ErrorLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FunctionName,
        
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $errorDetails = ""
    if ($ErrorRecord) { 
        $errorDetails = " - " + $ErrorRecord.Exception.GetType().Name + ": " + $ErrorRecord.Exception.Message
    }
    $logMessage = "[$timestamp] ERROR in " + $FunctionName + ": " + $ErrorMessage + $errorDetails
    
    # Output in console window
    Write-Host $logMessage -ForegroundColor Red
    
    # Add to global error log
    $global:errorLog += $logMessage
}

#region Helper Functions
# Function to safely disable a service
function Disable-ServiceSafely {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoStopOnError = $false
    )
    
    try {
        Write-Host "Attempting to disable service: $DisplayName ($ServiceName)..." -ForegroundColor Cyan
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($service) {
            # Try to stop the service if it's running
            if ($service.Status -eq 'Running') {
                try {
                    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                    Write-Host "Stopped service: $DisplayName" -ForegroundColor Green
                }
                catch {
                    $errorMsg = "Could not stop service. Reason: " + $_.Exception.Message
                    Write-ErrorLog -FunctionName "Disable-ServiceSafely" -ErrorMessage $errorMsg -ErrorRecord $_
                    
                    # If NoStopOnError is not specified, exit the function
                    if (-not $NoStopOnError) {
                        return
                    }
                }
            }
            
            # Try to disable the service
            try {
                Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
                Write-Host "Disabled service: $DisplayName" -ForegroundColor Green
                
                # Verify the change was applied - correct property name 'StartType' -> 'StartupType'
                $updatedService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($updatedService -and $updatedService.StartupType -ne 'Disabled') {
                    Write-Host "Warning: Service reports status after attempted disable" -ForegroundColor Yellow
                }
            }
            catch {
                $errorMsg = "Could not set service to 'Disabled'. Reason: " + $_.Exception.Message
                Write-ErrorLog -FunctionName "Disable-ServiceSafely" -ErrorMessage $errorMsg -ErrorRecord $_
            }
        } else {
            Write-Host "Service not found: $DisplayName" -ForegroundColor Yellow
        }
    }
    catch {
        $errorMsg = "General error in service management. Reason: " + $_.Exception.Message
        Write-ErrorLog -FunctionName "Disable-ServiceSafely" -ErrorMessage $errorMsg -ErrorRecord $_
    }
}

# Function to ensure registry path exists and properly handle errors
function Ensure-RegistryPath {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    if (!(Test-Path $Path)) {
        try {
            Write-Host "Creating registry path: $Path" -ForegroundColor Cyan
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            
            # Verify path was created
            if (Test-Path $Path) {
                Write-Host "Registry path created successfully: $Path" -ForegroundColor Green
                return $true
            } else {
                $errorMsg = "Registry path could not be created"
                Write-ErrorLog -FunctionName "Ensure-RegistryPath" -ErrorMessage $errorMsg
                return $false
            }
        }
        catch {
            $errorMsg = "Error creating registry path. Reason: " + $_.Exception.Message
            Write-ErrorLog -FunctionName "Ensure-RegistryPath" -ErrorMessage $errorMsg -ErrorRecord $_
            return $false
        }
    } else {
        Write-Verbose "Registry path already exists: $Path"
        return $true # Rückgabewert korrigiert auf true
    }
}
#endregion

#region Firewall configuration
Write-Host "Configuring firewall for GuardMonitor..." -ForegroundColor Cyan
# Remove any existing rule first to avoid duplicates
Remove-NetFirewallRule -DisplayName "Allow GuardMonitor" -ErrorAction SilentlyContinue

# Create new firewall rule - more specific parameters
try {
    New-NetFirewallRule -DisplayName "Allow GuardMonitor" -Direction Inbound -Action Allow `
        -Program "C:\ProgramData\Guard.ch\guardsrv.exe" -Protocol TCP -LocalPort 60000 `
        -Profile Any -Description "Allows GuardMonitor to receive incoming connections" `
        -Enabled True -ErrorAction Stop
    Write-Host "Firewall rule created successfully." -ForegroundColor Green
} catch {
    $errorMsg = "Firewall rule could not be created. Reason: " + $_.Exception.Message
    Write-ErrorLog -FunctionName "FirewallConfiguration" -ErrorMessage $errorMsg -ErrorRecord $_
}
# Function to radically disable updates for specific applications
function Disable-ApplicationUpdates {
    param (
        [Parameter(Mandatory=$true)]
        [string]$PackageName
    )
    
    Write-Host "Applying radical update prevention for $PackageName..." -ForegroundColor Yellow
    
    switch ($PackageName.ToLower()) {
        "googlechrome" {
            # Disable Chrome updates completely
            try {
                # Registry settings to disable updates
                $chromePaths = @(
                    "HKLM:\SOFTWARE\Policies\Google\Update",
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Update",
                    "HKCU:\SOFTWARE\Policies\Google\Update"
                )
                
                foreach ($path in $chromePaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "UpdateDefault" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DisableAutoUpdateChecksCheckboxValue" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" -Value 0 -Type DWord -Force
                }
                
                # Kill and disable Chrome update services
                Stop-Process -Name "GoogleUpdate*" -Force -ErrorAction SilentlyContinue
                Disable-ServiceSafely -ServiceName "gupdate" -DisplayName "Google Update Service (gupdate)"
                Disable-ServiceSafely -ServiceName "gupdatem" -DisplayName "Google Update Service (gupdatem)"
                
                # Remove Chrome update scheduler tasks
                Get-ScheduledTask -TaskName "*Google*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
                
                # Delete update files and folders
                $updatePaths = @(
                    "$env:ProgramFiles\Google\Update",
                    "$env:ProgramFiles(x86)\Google\Update",
                    "$env:LOCALAPPDATA\Google\Update"
                )
                foreach ($updatePath in $updatePaths) {
                    if (Test-Path $updatePath) {
                        Remove-Item -Path $updatePath -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed Chrome update directory: $updatePath" -ForegroundColor Green
                    }
                }
                
                Write-Host "Chrome updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Chrome updates" -ErrorRecord $_
            }
        }
        
        "firefox" {
            try {
                # Firefox update prevention
                $firefoxPaths = @(
                    "HKLM:\SOFTWARE\Policies\Mozilla\Firefox",
                    "HKCU:\SOFTWARE\Policies\Mozilla\Firefox"
                )
                
                foreach ($path in $firefoxPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "DisableAppUpdate" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ManualAppUpdateOnly" -Value 1 -Type DWord -Force
                }
                
                # Find Firefox installation directory and modify configuration
                $firefoxDirs = @(
                    "$env:ProgramFiles\Mozilla Firefox",
                    "$env:ProgramFiles(x86)\Mozilla Firefox"
                )
                
                foreach ($firefoxDir in $firefoxDirs) {
                    if (Test-Path $firefoxDir) {
                        # Create mozilla.cfg to disable updates
                        $configContent = @"
//
lockPref("app.update.enabled", false);
lockPref("app.update.auto", false);
lockPref("app.update.mode", 0);
lockPref("app.update.service.enabled", false);
"@
                        $configContent | Out-File -FilePath "$firefoxDir\mozilla.cfg" -Encoding ASCII -Force
                        
                        # Modify local-settings.js
                        $defaultsDir = "$firefoxDir\defaults\pref"
                        if (!(Test-Path $defaultsDir)) {
                            New-Item -Path $defaultsDir -ItemType Directory -Force | Out-Null
                        }
                        'pref("general.config.filename", "mozilla.cfg");' + "`n" + 'pref("general.config.obscure_value", 0);' | Out-File -FilePath "$defaultsDir\local-settings.js" -Encoding ASCII -Force
                        
                        # Remove update service executables
                        $updateFiles = @("updater.exe", "maintenanceservice.exe", "maintenanceservice_installer.exe")
                        foreach ($file in $updateFiles) {
                            $filePath = Join-Path $firefoxDir $file
                            if (Test-Path $filePath) {
                                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                
                # Disable Firefox Maintenance Service
                Disable-ServiceSafely -ServiceName "MozillaMaintenance" -DisplayName "Mozilla Maintenance Service"
                
                Write-Host "Firefox updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Firefox updates" -ErrorRecord $_
            }
        }
        
        "brave" {
            try {
                # Brave uses Chromium update mechanism
                $bravePaths = @(
                    "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
                    "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"
                )
                
                foreach ($path in $bravePaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "UpdatesSuppressed" -Value 1 -Type DWord -Force
                }
                
                # Remove Brave update tasks
                Get-ScheduledTask -TaskName "*Brave*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
                
                Write-Host "Brave updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Brave updates" -ErrorRecord $_
            }
        }
        
        "microsoft-edge" {
            try {
                # Edge update prevention
                $edgePaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                    "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate",
                    "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
                )
                
                foreach ($path in $edgePaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "UpdateDefault" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "UpdatesSuppressed" -Value 1 -Type DWord -Force
                }
                
                # Disable Edge update services
                Disable-ServiceSafely -ServiceName "edgeupdate" -DisplayName "Microsoft Edge Update Service (edgeupdate)"
                Disable-ServiceSafely -ServiceName "edgeupdatem" -DisplayName "Microsoft Edge Update Service (edgeupdatem)"
                
                # Remove Edge update tasks
                Get-ScheduledTask -TaskName "*Edge*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
                
                Write-Host "Microsoft Edge updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Edge updates" -ErrorRecord $_
            }
        }
        
        "opera" {
            try {
                # Opera update prevention
                $operaPaths = @(
                    "HKLM:\SOFTWARE\Policies\Opera Software\Opera",
                    "HKCU:\SOFTWARE\Policies\Opera Software\Opera"
                )
                
                foreach ($path in $operaPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "UpdatesSuppressed" -Value 1 -Type DWord -Force
                }
                
                # Find and disable Opera update assistant
                $operaDirs = @(
                    "$env:ProgramFiles\Opera",
                    "$env:ProgramFiles(x86)\Opera",
                    "$env:LOCALAPPDATA\Programs\Opera"
                )
                
                foreach ($operaDir in $operaDirs) {
                    if (Test-Path $operaDir) {
                        $updateFiles = Get-ChildItem -Path $operaDir -Recurse -Name "opera_autoupdate*" -ErrorAction SilentlyContinue
                        foreach ($file in $updateFiles) {
                            Remove-Item -Path (Join-Path $operaDir $file) -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                
                Write-Host "Opera updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Opera updates" -ErrorRecord $_
            }
        }
        
        "vivaldi" {
            try {
                # Vivaldi update prevention (Chromium-based)
                $vivaldiPaths = @(
                    "HKLM:\SOFTWARE\Policies\Vivaldi",
                    "HKCU:\SOFTWARE\Policies\Vivaldi"
                )
                
                foreach ($path in $vivaldiPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "UpdatesSuppressed" -Value 1 -Type DWord -Force
                }
                
                Write-Host "Vivaldi updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Vivaldi updates" -ErrorRecord $_
            }
        }
        
        "vscode" {
            try {
                # VS Code update prevention
                $vscodePaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\VSCode",
                    "HKCU:\SOFTWARE\Policies\Microsoft\VSCode"
                )
                
                foreach ($path in $vscodePaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "DisableUpdateCheck" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DisableUpdate" -Value 1 -Type DWord -Force
                }
                
                # Find VS Code installation and modify settings
                $vscodeDirs = @(
                    "$env:ProgramFiles\Microsoft VS Code",
                    "$env:ProgramFiles(x86)\Microsoft VS Code",
                    "$env:LOCALAPPDATA\Programs\Microsoft VS Code"
                )
                
                foreach ($vscodeDir in $vscodeDirs) {
                    if (Test-Path $vscodeDir) {
                        # Remove update executable
                        $updateExe = Join-Path $vscodeDir "resources\app\out\vs\code\electron-main\updater.exe"
                        if (Test-Path $updateExe) {
                            Remove-Item -Path $updateExe -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                
                Write-Host "VS Code updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable VS Code updates" -ErrorRecord $_
            }
        }
        
        "vlc" {
            try {
                # VLC update prevention
                $vlcPath = "HKLM:\SOFTWARE\VideoLAN\VLC"
                if (Test-Path $vlcPath) {
                    Set-ItemProperty -Path $vlcPath -Name "IsFirstRun" -Value 0 -Type DWord -Force
                }
                
                # Find VLC installation and remove updater
                $vlcDirs = @(
                    "$env:ProgramFiles\VideoLAN\VLC",
                    "$env:ProgramFiles(x86)\VideoLAN\VLC"
                )
                
                foreach ($vlcDir in $vlcDirs) {
                    if (Test-Path $vlcDir) {
                        $updateFiles = @("vlc-updater.exe", "vlc-cache-gen.exe")
                        foreach ($file in $updateFiles) {
                            $filePath = Join-Path $vlcDir $file
                            if (Test-Path $filePath) {
                                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                
                Write-Host "VLC updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable VLC updates" -ErrorRecord $_
            }
        }
        
        "adobereader" {
            try {
                # Adobe Reader update prevention
                $adobePaths = @(
                    "HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer",
                    "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader\DC\Installer",
                    "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"
                )
                
                foreach ($path in $adobePaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "DisableUpdates" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $path -Name "UpdateMode" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                }
                
                # Disable Adobe services
                $adobeServices = @("AdobeARMservice", "Adobe Acrobat Update Service", "AdobeUpdateService")
                foreach ($service in $adobeServices) {
                    Disable-ServiceSafely -ServiceName $service -DisplayName $service
                }
                
                # Remove Adobe update tasks
                Get-ScheduledTask -TaskName "*Adobe*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
                
                Write-Host "Adobe Reader updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Adobe Reader updates" -ErrorRecord $_
            }
        }
        
        "notepadplusplus" {
            try {
                # Notepad++ update prevention
                $nppDirs = @(
                    "$env:ProgramFiles\Notepad++",
                    "$env:ProgramFiles(x86)\Notepad++"
                )
                
                foreach ($nppDir in $nppDirs) {
                    if (Test-Path $nppDir) {
                        # Create config to disable updates
                        $configPath = Join-Path $nppDir "config.xml"
                        if (Test-Path $configPath) {
                            # Backup and modify existing config
                            $configContent = Get-Content $configPath -Raw
                            $configContent = $configContent -replace 'doCheckUpdate="yes"', 'doCheckUpdate="no"'
                            $configContent = $configContent -replace 'enableAutoUpdate="yes"', 'enableAutoUpdate="no"'
                            $configContent | Out-File $configPath -Encoding UTF8 -Force
                        } else {
                            # Create minimal config to disable updates
                            $disableUpdateConfig = @'
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <GUIConfigs>
        <GUIConfig name="noUpdate">yes</GUIConfig>
        <GUIConfig name="Auto-detection">no</GUIConfig>
    </GUIConfigs>
</NotepadPlus>
'@
                            $disableUpdateConfig | Out-File $configPath -Encoding UTF8 -Force
                        }
                        
                        # Remove updater executable
                        $updaterPath = Join-Path $nppDir "updater\GUP.exe"
                        if (Test-Path $updaterPath) {
                            Remove-Item -Path $updaterPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                
                Write-Host "Notepad++ updates permanently disabled" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to disable Notepad++ updates" -ErrorRecord $_
            }
        }
        
        default {
            # Generic update prevention for other applications
            try {
                Write-Host "Applying generic update prevention for $PackageName..." -ForegroundColor Cyan
                
                # Remove common update-related scheduled tasks
                $updateTasks = Get-ScheduledTask -TaskName "*$PackageName*" -ErrorAction SilentlyContinue
                foreach ($task in $updateTasks) {
                    if ($task.TaskName -match "update|upgrade") {
                        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                        Write-Host "Removed update task: $($task.TaskName)" -ForegroundColor Green
                    }
                }
                
                # Look for and disable common update services
                $services = Get-Service -Name "*$PackageName*" -ErrorAction SilentlyContinue
                foreach ($service in $services) {
                    if ($service.Name -match "update|upgrade") {
                        Disable-ServiceSafely -ServiceName $service.Name -DisplayName $service.DisplayName
                    }
                }
                
                Write-Host "Generic update prevention applied for $PackageName" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to apply generic update prevention for $PackageName" -ErrorRecord $_
            }
        }
    }
}

#endregion

#region Chocolatey Installation
Write-Host "Installing Chocolatey and software..." -ForegroundColor Cyan
try {
    # Install chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Host "Chocolatey installed successfully" -ForegroundColor Green
        
    # Disable Chocolatey auto-updates
    choco feature disable --name="autouninstaller" --confirm
    choco feature disable --name="checksumFiles" --confirm
    choco feature disable --name="showDownloadProgress" --confirm
    choco feature disable --name="autoUpgrade" --confirm
    Write-Host "Chocolatey auto-updates disabled" -ForegroundColor Green
    
    # Refresh environment variables to include Chocolatey
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    # Configure temporary download path
    $tempPath = "$env:TEMP\ChocolateyTemp"
    if (!(Test-Path $tempPath)) {
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
    }
    $env:TEMP = $tempPath
    
    # Install specified software with no auto-updates
    Write-Host "Installing software packages (this may take some time)..." -ForegroundColor Cyan
    
    # Install each package individually with appropriate flags to prevent updates
    $softwarePackages = @(
        "googlechrome",
        "firefox",
        "brave",
        "tor-browser",
        "microsoft-edge",
        "opera", 
        "vivaldi",
        "chromium",
        "wireshark",
        "adobereader",
        "7zip",
        "vscode",
        "vlc",
        "putty",
        "notepadplusplus"
    )
    
    foreach ($package in $softwarePackages) {
        Write-Host "Installing $package..." -ForegroundColor Cyan
        try {
            $chocoResult = choco install $package -y --ignore-checksums --no-progress --limit-output --no-autouninstaller
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$package installation completed successfully" -ForegroundColor Green
                
                # Apply radical update prevention measures for each package
                Write-Host "Applying radical update prevention for $package..." -ForegroundColor Yellow
                Disable-ApplicationUpdates -PackageName $package
            } else {
                $errorMsg = "Package installation completed with exit code: $LASTEXITCODE"
                Write-ErrorLog -FunctionName "ChocoInstall" -ErrorMessage $errorMsg -ErrorRecord $null
            }
        } catch {
            $errorMsg = "Error during package installation. Reason: " + $_.Exception.Message
            Write-ErrorLog -FunctionName "ChocoInstall" -ErrorMessage $errorMsg -ErrorRecord $_
            # Continue with other packages
        }
    }
    
    # Completely disable Chocolatey background services
    Disable-ServiceSafely -ServiceName "chocolatey-agent" -DisplayName "Chocolatey Agent Service"
    
    Write-Host "Software installation completed" -ForegroundColor Green
    
    # Apply nuclear-level update prevention measures
    Write-Host "Applying nuclear-level update prevention measures..." -ForegroundColor Red
    
    # Block update domains via hosts file
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $updateDomains = @(
            "update.googleapis.com",
            "clients2.google.com",
            "clients4.google.com",
            "edgedl.me.gvt1.com",
            "dl.google.com",
            "update.microsoft.com",
            "windowsupdate.microsoft.com",
            "download.windowsupdate.com",
            "ntservicepack.microsoft.com",
            "aus5.mozilla.org",
            "download.mozilla.org",
            "updates.brave.com",
            "laptop-updates.brave.com",
            "go-updater.brave.com",
            "updates.opera.com",
            "autoupdate.opera.com",
            "update.vivaldi.com",
            "autoupdate.vivaldi.com",
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "armmf.adobe.com",
            "download.adobe.com",
            "update.code.visualstudio.com",
            "vscode.download.prss.microsoft.com",
            "notepad-plus-plus.org"
        )
        
        $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
        $newEntries = @()
        
        foreach ($domain in $updateDomains) {
            if ($hostsContent -notmatch [regex]::Escape($domain)) {
                $newEntries += "127.0.0.1 $domain"
                $newEntries += "::1 $domain"
            }
        }
        
        if ($newEntries.Count -gt 0) {
            Add-Content -Path $hostsPath -Value "`n# Block update domains" -Force
            Add-Content -Path $hostsPath -Value $newEntries -Force
            Write-Host "Blocked $($updateDomains.Count) update domains in hosts file" -ForegroundColor Green
        }
        
        # Flush DNS cache
        ipconfig /flushdns | Out-Null
    } catch {
        Write-ErrorLog -FunctionName "BlockUpdateDomains" -ErrorMessage "Failed to block update domains" -ErrorRecord $_
    }
    
    # Create firewall rules to block outbound connections to update servers
    try {
        $updatePorts = @(80, 443, 8080, 8443)
        foreach ($port in $updatePorts) {
            # Block common update domains on these ports
            New-NetFirewallRule -DisplayName "Block Updates Port $port" -Direction Outbound -Action Block `
                -Protocol TCP -RemotePort $port -RemoteAddress @("update.googleapis.com", "windowsupdate.microsoft.com", "download.mozilla.org") `
                -ErrorAction SilentlyContinue
        }
        Write-Host "Created firewall rules to block update connections" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "CreateUpdateFirewallRules" -ErrorMessage "Failed to create update blocking firewall rules" -ErrorRecord $_
    }
    
    # Remove all update-related scheduled tasks system-wide
    try {
        $updateTaskKeywords = @("update", "upgrade", "autoupdate", "GoogleUpdate", "EdgeUpdate", "Adobe", "Mozilla")
        foreach ($keyword in $updateTaskKeywords) {
            Get-ScheduledTask -TaskName "*$keyword*" -ErrorAction SilentlyContinue | 
                Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host "Removed all update-related scheduled tasks" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "RemoveUpdateTasks" -ErrorMessage "Failed to remove update tasks" -ErrorRecord $_
    }
    
    # Disable Windows Installer for MSI-based updates
    try {
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "DisableMSI" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "DisablePatch" -Value 1 -Type DWord -Force
        Write-Host "Disabled Windows Installer for updates" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "DisableWindowsInstaller" -ErrorMessage "Failed to disable Windows Installer" -ErrorRecord $_
    }
    
    # Set network as metered to prevent automatic downloads
    try {
        Ensure-RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -Name "Ethernet" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -Name "WiFi" -Value 2 -Type DWord -Force
        Write-Host "Set network as metered to prevent automatic updates" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "SetMeteredNetwork" -ErrorMessage "Failed to set metered network" -ErrorRecord $_
    }
    
    Write-Host "Nuclear-level update prevention measures completed" -ForegroundColor Red
    
    # PHYSICAL DESTRUCTION: Remove update executables and replace with dummy files
    Write-Host "DESTROYING UPDATE MECHANISMS AT FILE SYSTEM LEVEL..." -ForegroundColor Magenta
    
    try {
        # Common update executable locations to destroy
        $updateExecutables = @(
            "$env:ProgramFiles\Google\Update\GoogleUpdate.exe",
            "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.exe",
            "$env:ProgramFiles\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            "$env:ProgramFiles(x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            "$env:ProgramFiles\Mozilla Firefox\updater.exe",
            "$env:ProgramFiles(x86)\Mozilla Firefox\updater.exe",
            "$env:ProgramFiles\Mozilla Firefox\maintenanceservice.exe",
            "$env:ProgramFiles(x86)\Mozilla Firefox\maintenanceservice.exe",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*update*",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*update*"
        )
        
        # Destroy update executables by replacing them with dummy files
        foreach ($executable in $updateExecutables) {
            if (Test-Path $executable) {
                try {
                    # Take ownership and remove read-only attributes
                    takeown /f $executable /a | Out-Null
                    icacls $executable /grant Administrators:F | Out-Null
                    attrib -r -s -h $executable | Out-Null
                    
                    # Delete original and replace with dummy
                    Remove-Item -Path $executable -Force -ErrorAction Stop
                    "DISABLED BY GUARD SYSTEM" | Out-File -FilePath $executable -Encoding ASCII -Force
                    
                    # Make the dummy file unmodifiable
                    attrib +r +s +h $executable | Out-Null
                    Write-Host "DESTROYED: $executable" -ForegroundColor Red
                } catch {
                    Write-Host "Could not destroy: $executable" -ForegroundColor Yellow
                }
            }
        }
        
        # Destroy common update directories completely
        $updateDirectories = @(
            "$env:ProgramFiles\Google\Update",
            "$env:ProgramFiles(x86)\Google\Update",
            "$env:LOCALAPPDATA\Google\Update",
            "$env:ProgramFiles\Microsoft\EdgeUpdate",
            "$env:ProgramFiles(x86)\Microsoft\EdgeUpdate",
            "$env:LOCALAPPDATA\Microsoft\EdgeUpdate",
            "$env:ProgramData\Adobe\ARM",
            "$env:ProgramFiles\Common Files\Adobe\ARM",
            "$env:ProgramFiles(x86)\Common Files\Adobe\ARM"
        )
        
        foreach ($directory in $updateDirectories) {
            if (Test-Path $directory) {
                try {
                    # Recursively take ownership
                    takeown /f $directory /r /a | Out-Null
                    icacls $directory /grant Administrators:F /t | Out-Null
                    
                    # Remove the directory completely
                    Remove-Item -Path $directory -Recurse -Force -ErrorAction Stop
                    
                    # Create a dummy file in its place to prevent recreation
                    "DESTROYED BY GUARD SYSTEM" | Out-File -FilePath $directory -Encoding ASCII -Force
                    attrib +r +s +h $directory | Out-Null
                    
                    Write-Host "DESTROYED DIRECTORY: $directory" -ForegroundColor Red
                } catch {
                    Write-Host "Could not destroy directory: $directory" -ForegroundColor Yellow
                }
            }
        }
        
        # Find and destroy any remaining update-related executables
        $systemDrives = @("C:")
        foreach ($drive in $systemDrives) {
            $updateFiles = Get-ChildItem -Path $drive -Recurse -Include @("*update*.exe", "*upgrade*.exe", "*autoupdate*.exe") -ErrorAction SilentlyContinue | 
                Where-Object { $_.Directory -notmatch "Guard|Windows|System32|WinSxS" }
            
            foreach ($file in $updateFiles) {
                try {
                    takeown /f $file.FullName /a | Out-Null
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    "DESTROYED BY GUARD SYSTEM" | Out-File -FilePath $file.FullName -Encoding ASCII -Force
                    attrib +r +s +h $file.FullName | Out-Null
                    Write-Host "DESTROYED UPDATE FILE: $($file.FullName)" -ForegroundColor Red
                } catch {
                    Write-Host "Could not destroy: $($file.FullName)" -ForegroundColor Yellow
                }
            }
        }
        
        Write-Host "UPDATE MECHANISM DESTRUCTION COMPLETED" -ForegroundColor Magenta
    } catch {
        Write-ErrorLog -FunctionName "DestroyUpdateMechanisms" -ErrorMessage "Failed to destroy update mechanisms" -ErrorRecord $_
    }
}
catch {
    Write-ErrorLog -FunctionName "ChocolateySetup" -ErrorMessage "Error installing Chocolatey or software" -ErrorRecord $_
}
#endregion

#region Disable Windows Update
Write-Host "Disabling Windows Update..." -ForegroundColor Cyan

# Using multiple methods to ensure Windows Update is disabled
try {
    # Group Policy method (works on Pro/Enterprise editions)
    if ((Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -ne 1) {
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        Ensure-RegistryPath $auPath
        Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 1 -Type DWord -Force
        Write-Host "Windows Update group policy settings applied" -ForegroundColor Green
    }

    # Registry method (works on all editions)
    Ensure-RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 1 -Type DWord -Force

    # Windows Update service method
    Disable-ServiceSafely -ServiceName "wuauserv" -DisplayName "Windows Update"
    Disable-ServiceSafely -ServiceName "UsoSvc"   -DisplayName "Update Orchestrator Service"
    Write-Host "Windows Update disabled successfully" -ForegroundColor Green

    # Force removal of Windows Update components
    Write-Host "Stopping and removing Windows Update services..." -ForegroundColor Cyan
    try {
        Stop-Service -Name wuauserv,UsoSvc,WaaSMedicSvc -Force -ErrorAction SilentlyContinue
        sc.exe delete wuauserv    | Out-Null
        sc.exe delete UsoSvc      | Out-Null
        sc.exe delete WaaSMedicSvc| Out-Null
        Write-Host "Windows Update services removed" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "RemoveWindowsUpdateServices" -ErrorMessage "Failed to remove update services" -ErrorRecord $_
    }

    Write-Host "Removing SoftwareDistribution and catroot2 folders..." -ForegroundColor Cyan
    try {
        Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse -Force -ErrorAction Stop
        Remove-Item -Path "C:\Windows\System32\catroot2"        -Recurse -Force -ErrorAction Stop
        Write-Host "Update folders removed successfully" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "RemoveUpdateFolders" -ErrorMessage "Failed to delete update folders" -ErrorRecord $_
    }

    Write-Host "Unregistering Windows Update scheduled tasks..." -ForegroundColor Cyan
    try {
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\*" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Windows Update tasks removed" -ForegroundColor Green
    } catch {
        Write-ErrorLog -FunctionName "RemoveUpdateTasks" -ErrorMessage "Failed to unregister update tasks" -ErrorRecord $_
    }
}
catch {
    Write-ErrorLog -FunctionName "DisableWindowsUpdate" -ErrorMessage "Error disabling Windows Update" -ErrorRecord $_
}
#endregion

#region Install Guard software
Write-Host "Setting up Guard.ch..." -ForegroundColor Cyan

# Ensure the Guard directory exists
$guardDir = "$env:ProgramData\Guard.ch"
if (!(Test-Path $guardDir)) {
    try {
        New-Item -Path $guardDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Created Guard directory: $guardDir" -ForegroundColor Green
    }
    catch {
        Write-ErrorLog -FunctionName "InstallGuardSoftware" -ErrorMessage "Failed to create Guard directory" -ErrorRecord $_
        return
    }
}

# Download guardsrv.exe to the correct location
$guardUrl  = "https://raw.githubusercontent.com/saschazesiger/guarddownload-sl52610lmu7ayhb56tacs/refs/heads/main/guardsrv.exe"
$guardDest = "$guardDir\guardsrv.exe"

try {
    Write-Host "Downloading guardsrv.exe from $guardUrl..." -ForegroundColor Cyan
    Write-Host "Target location: $guardDest" -ForegroundColor Cyan
    # Download the file
    Invoke-WebRequest -Uri $guardUrl -OutFile $guardDest -ErrorAction Stop
}
catch {
    Write-ErrorLog -FunctionName "InstallGuardSoftware" -ErrorMessage "Failed to download guardsrv.exe to $guardDest" -ErrorRecord $_
}
#endregion

#region Configure Auto Login
Write-Host "Setting up auto login..." -ForegroundColor Cyan

try {
    # Registry path for auto login
    $winLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    
    # Set auto login parameters
    Set-ItemProperty -Path $winLogonPath -Name "AutoAdminLogon" -Value "1" -Type String -Force
    Set-ItemProperty -Path $winLogonPath -Name "DefaultUserName" -Value "user" -Type String -Force
    Set-ItemProperty -Path $winLogonPath -Name "DefaultPassword" -Value "GuardUser5046!" -Type String -Force
    Set-ItemProperty -Path $winLogonPath -Name "DefaultDomainName" -Value "." -Type String -Force
    
    Write-Host "Auto login configured successfully" -ForegroundColor Green
}
catch {
    Write-ErrorLog -FunctionName "ConfigureAutoLogin" -ErrorMessage "Error configuring auto login" -ErrorRecord $_
}
#endregion

#region Limit Concurrent Sessions
Write-Host "Configuring session limits..." -ForegroundColor Cyan

try {
    # Limit concurrent sessions for user account to 1
    $terminalServicesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    Ensure-RegistryPath $terminalServicesPath
    
    # Set maximum concurrent sessions to 1
    Set-ItemProperty -Path $terminalServicesPath -Name "MaxInstanceCount" -Value 1 -Type DWord -Force
    
    # Configure Terminal Services user settings
    $tsUserPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Ensure-RegistryPath $tsUserPath
    
    # Set user-specific session limit
    $userProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    Ensure-RegistryPath $userProfilePath
    
    # Configure RDP connection limits
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $rdpPath) {
        Set-ItemProperty -Path $rdpPath -Name "MaxInstanceCount" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $rdpPath -Name "MaxConnectionTime" -Value 0 -Type DWord -Force
    }
    
    Write-Host "Session limits configured successfully (max 1 concurrent session)" -ForegroundColor Green
}
catch {
    Write-ErrorLog -FunctionName "ConfigureSessionLimits" -ErrorMessage "Error configuring session limits" -ErrorRecord $_
}
#endregion

# Disable lock screen
Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1 -Type DWord -Force

#region Clear Event Logs
# Clear event logs to free up space (with better error handling)
try {
    $eventLogs = Get-WinEvent -ListLog * -ErrorAction Stop | Where-Object { $_.RecordCount -gt 0 -and $_.IsEnabled -eq $true }
    foreach ($log in $eventLogs) {
        try {
            [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$($log.LogName)")
        } catch {
            Write-Host "Could not clear event log" -ForegroundColor Yellow
        }
    }
    Write-Host "Event logs cleared successfully" -ForegroundColor Green
} catch {
    Write-Host "Error accessing event logs" -ForegroundColor Yellow
}
#endregion

#region Remove all Tasks
Get-ScheduledTask -TaskName "*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
#endregion

#region Create GuardMonitor Task
Write-Host "Setting up GuardMonitor scheduled task..." -ForegroundColor Cyan

# Define the XML content directly in the script
$taskXmlContent = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-12-13T12:57:55.7234893</Date>
    <Author>Administrator</Author>
    <URI>\GuardMonitor</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <AllowHardTerminate>false</AllowHardTerminate>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <RestartOnFailure>
      <Count>10</Count>
      <Interval>PT1M</Interval>
    </RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT0S</Delay>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\ProgramData\Guard.ch\guardsrv.exe</Command>
    </Exec>
  </Actions>
</Task>
'@

try {
    # Remove task if it already exists
    $existingTask = Get-ScheduledTask -TaskName "GuardMonitor" -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName "GuardMonitor" -Confirm:$false -ErrorAction Stop
        Write-Host "Removed existing GuardMonitor task" -ForegroundColor Cyan
    }
    
    # Create temporary XML file to use with schtasks (as Register-ScheduledTask -Xml sometimes has encoding issues)
    $tempXmlPath = "$env:TEMP\GuardMonitor_temp.xml"
    $taskXmlContent | Out-File -FilePath $tempXmlPath -Encoding Unicode -Force
    
    # Create the new task using schtasks for better XML compatibility
    $result = schtasks /Create /TN "GuardMonitor" /XML $tempXmlPath /F
    
    # Clean up temporary file
    Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
    
    # Verify task was created
    if (Get-ScheduledTask -TaskName "GuardMonitor" -ErrorAction SilentlyContinue) {
        Write-Host "GuardMonitor task created successfully from embedded XML" -ForegroundColor Green
    } else {
        Write-Host "Failed to verify task creation. Output: $result" -ForegroundColor Yellow
    }
}
catch {
    Write-ErrorLog -FunctionName "CreateGuardMonitorTask" -ErrorMessage "Error creating GuardMonitor scheduled task from embedded XML" -ErrorRecord $_

    # Fallback: Try to create the task with PowerShell commands
    try {
        $action = New-ScheduledTaskAction -Execute "C:\ProgramData\Guard.ch\guardsrv.exe"
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "user"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden -MultipleInstances IgnoreNew -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)
        $principal = New-ScheduledTaskPrincipal -UserId "user" -LogonType Password -RunLevel Highest
        
        Register-ScheduledTask -TaskName "GuardMonitor" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop
        Write-Host "GuardMonitor task created with PowerShell commands as fallback" -ForegroundColor Green
    }
    catch {
        Write-ErrorLog -FunctionName "CreateGuardMonitorTaskFallback" -ErrorMessage "Error creating GuardMonitor task with PowerShell commands" -ErrorRecord $_
    }
}
#endregion

# Final message and clean output
Write-Host "  INSTALLATION COMPLETED SUCCESSFULLY" -ForegroundColor Green

# Stop the transcript that was started at the beginning
Stop-Transcript