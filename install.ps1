# Script: install.ps1
# Purpose: Provision GuardMonitor, install required software, harden system, and disable auto-updates/first-run prompts.
# Notes:
# - Requires administrative privileges.
# - Logs are written to %TEMP% with a timestamped filename via Start-Transcript.
# - Functions provide safe helpers for registry, services, first-run suppression, and update hardening.

#region Setup and initialization
# Start transcript logging with timestamp for better tracking
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Start-Transcript -Path "$env:TEMP\guard_install_$timestamp.log" -Force

# Ensure TLS 1.2 for all web requests (older .NET defaults may fail GitHub/Chocolatey downloads)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Ensure the script is running with Administrator privileges
function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-IsAdministrator)) {
    Write-Host "Dieses Skript muss als Administrator ausgeführt werden." -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

# Global variable for enhanced error logging
$global:errorLog = @()

# Function for better error logs
<#
.SYNOPSIS
  Writes a standardized error entry to console and a global in-memory error log.
.DESCRIPTION
  Wraps error handling with timestamp, function name and optional ErrorRecord details.
.PARAMETER FunctionName
  Logical name of the caller used for tracing (e.g., Disable-ServiceSafely).
.PARAMETER ErrorMessage
  Human-friendly error message explaining the failure.
.PARAMETER ErrorRecord
  Optional PowerShell ErrorRecord; if provided, exception type/message will be appended.
#>
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
<#
.SYNOPSIS
  Stops and disables a Windows service with robust error handling.
.PARAMETER ServiceName
  The service name (not display name).
.PARAMETER DisplayName
  Friendly name printed to console for user clarity.
.PARAMETER NoStopOnError
  When set, failures to stop do not abort disabling (best-effort mode).
#>
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
                
                # Verify the change was applied using CIM (reliable StartMode)
                $svcInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                if ($svcInfo -and $svcInfo.StartMode -ne 'Disabled') {
                    Write-Host "Warning: Service did not report Disabled start type after attempted change" -ForegroundColor Yellow
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
<#
.SYNOPSIS
  Ensures a registry key path exists (creates if missing).
.PARAMETER Path
  The registry path (e.g., HKLM:\SOFTWARE\Policies\... ).
.OUTPUTS
  [bool] True when the path exists/was created successfully; otherwise False.
#>
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
<#
.SYNOPSIS
  Applies application-specific update prevention (services, tasks, files, and policies).
.DESCRIPTION
  Targets known updaters for supported apps. Non-destructive where possible, with logging.
.PARAMETER PackageName
  Chocolatey package id or app key handled by the switch block (e.g., firefox, vscode).
#>
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
                        # Fix Get-ChildItem usage and remove by full path
                        $updateFiles = Get-ChildItem -Path (Join-Path $operaDir "*") -Recurse -Include "opera_autoupdate*" -File -ErrorAction SilentlyContinue
                        foreach ($file in $updateFiles) {
                            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
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

        "chromium" {
            try {
                # Chromium policies (mirror Chrome’s first-run suppression)
                $chromiumPolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Chromium",
                    "HKCU:\SOFTWARE\Policies\Chromium"
                )
                foreach ($path in $chromiumPolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "NoFirstRun" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "SuppressFirstRunDefaultBrowserPrompt" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ShowFirstRunBubble" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportAutofillFormData" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportBookmarks" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportHistory" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportSavedPasswords" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportSearchEngine" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "PromptForDownloadLocation" -Value 0 -Type DWord -Force
                }

                # Ensure "First Run" marker to hard-skip first-run UI
                $chrUserDataRoots = @(
                    "$env:LOCALAPPDATA\Chromium\User Data",
                    "$env:APPDATA\Chromium\User Data"
                )
                foreach ($root in $chrUserDataRoots) {
                    if (!(Test-Path $root)) { New-Item -Path $root -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
                    $firstRunPath = Join-Path $root "First Run"
                    if (!(Test-Path $firstRunPath)) { "" | Out-File -FilePath $firstRunPath -Encoding ASCII -Force }
                }

                # Chromium user default preferences (align with Chrome)
                $chrUserDirs = @(
                    "$env:LOCALAPPDATA\Chromium\User Data\Default",
                    "$env:APPDATA\Chromium\User Data\Default"
                )
                foreach ($dir in $chrUserDirs) {
                    if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
                    $prefs = @{
                        "profile" = @{
                            "default_content_setting_values" = @{
                                "notifications" = 2
                            }
                            "default_content_settings" = @{
                                "popups" = 0
                            }
                        }
                        "browser" = @{
                            "show_home_button" = $true
                            "check_default_browser" = $false
                        }
                        "distribution" = @{
                            "skip_first_run_ui" = $true
                            "show_welcome_page" = $false
                            "skip_profile_signin_promo" = $true
                            "import_search_engine" = $false
                            "import_history" = $false
                            "import_bookmarks" = $false
                            "import_home_page" = $false
                            "ping_delay" = 60
                            "do_not_create_any_shortcuts" = $true
                            "do_not_create_desktop_shortcut" = $true
                            "do_not_create_quick_launch_shortcut" = $true
                            "do_not_create_taskbar_shortcut" = $true
                            "do_not_register_for_update_launch" = $true
                        }
                        "first_run_tabs" = @()
                    } | ConvertTo-Json -Depth 5
                    $prefs | Out-File -FilePath (Join-Path $dir "Preferences") -Encoding UTF8 -Force
                }
                Write-Host "Chromium first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Disable-ApplicationUpdates" -ErrorMessage "Failed to configure Chromium first-run suppression" -ErrorRecord $_
            }
        }
    }
}
#endregion

#region Suppress First-Run Experiences Function Definition
# Function to create default user profiles and suppress first-run dialogs
<#
.SYNOPSIS
  Configures policies and user defaults to suppress welcome/first-run UX per application.
.DESCRIPTION
  Writes policy keys/files and opinionated defaults to reduce prompts on first launch.
.PARAMETER ApplicationName
  Logical application key (e.g., chrome, edge, firefox, vscode, vlc, 7zip).
#>
function Suppress-FirstRunExperiences {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ApplicationName
    )
    
    Write-Host "Configuring first-run suppression for $ApplicationName..." -ForegroundColor Yellow
    
    switch ($ApplicationName.ToLower()) {
        "chrome" {
            try {
                # Chrome Group Policy settings (both 32-bit and 64-bit)
                $chromePolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Google\Chrome",
                    "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome",
                    "HKCU:\SOFTWARE\Policies\Google\Chrome"
                )
                
                foreach ($path in $chromePolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "NoFirstRun" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "SuppressFirstRunDefaultBrowserPrompt" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ShowFirstRunBubble" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportAutofillFormData" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportBookmarks" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportHistory" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportSavedPasswords" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportSearchEngine" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "PromptForDownloadLocation" -Value 0 -Type DWord -Force
                    # Suppress sign-in and sync prompts
                    Set-ItemProperty -Path $path -Name "SyncDisabled" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "BrowserSignin" -Value 0 -Type DWord -Force
                    # Disable Privacy Sandbox prompts
                    Set-ItemProperty -Path $path -Name "PrivacySandboxEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "PrivacySandboxSettingsReconciliationEnabled" -Value 0 -Type DWord -Force
                }
                
                # Create Chrome initial preferences
                $chromeUserDirs = @(
                    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
                    "$env:APPDATA\Google\Chrome\User Data\Default"
                )
                
                foreach ($chromeUserDir in $chromeUserDirs) {
                    if (!(Test-Path $chromeUserDir)) {
                        New-Item -Path $chromeUserDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                    }
                    
                    # Create Preferences file to skip welcome screens and sign-in
                    $chromePrefs = @{
                        "profile" = @{
                            "default_content_setting_values" = @{
                                "notifications" = 2
                            }
                            "default_content_settings" = @{
                                "popups" = 0
                            }
                        }
                        "browser" = @{
                            "show_home_button" = $true
                            "check_default_browser" = $false
                        }
                        "distribution" = @{
                            "skip_first_run_ui" = $true
                            "show_welcome_page" = $false
                            "skip_profile_signin_promo" = $true
                            "import_search_engine" = $false
                            "import_history" = $false
                            "import_bookmarks" = $false
                            "import_home_page" = $false
                            "ping_delay" = 60
                            "do_not_create_any_shortcuts" = $true
                            "do_not_create_desktop_shortcut" = $true
                            "do_not_create_quick_launch_shortcut" = $true
                            "do_not_create_taskbar_shortcut" = $true
                            "do_not_register_for_update_launch" = $true
                        }
                        "privacy" = @{
                            "sandbox" = @{
                                "settings" = @{
                                    "enabled" = $false
                                }
                            }
                        }
                        "first_run_tabs" = @()
                    } | ConvertTo-Json -Depth 5
                    
                    $chromePrefs | Out-File -FilePath (Join-Path $chromeUserDir "Preferences") -Encoding UTF8 -Force
                }
                
                Write-Host "Chrome first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Chrome first-run suppression" -ErrorRecord $_
            }
        }
        
        "edge" {
            try {
                # Edge Group Policy settings
                $edgePolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                    "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
                )
                
                foreach ($path in $edgePolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "HideFirstRunExperience" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "FirstRunExperienceEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportOnFirstRun" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "StartupBoostEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force
                }
                
                Write-Host "Edge first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Edge first-run suppression" -ErrorRecord $_
            }
        }
        
        "firefox" {
            try {
                # Firefox Policy settings
                $firefoxPaths = @(
                    "HKLM:\SOFTWARE\Policies\Mozilla\Firefox",
                    "HKCU:\SOFTWARE\Policies\Mozilla\Firefox"
                )
                
                foreach ($path in $firefoxPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "DisableAppUpdate" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ManualAppUpdateOnly" -Value 1 -Type DWord -Force
                }
                
                # Firefox distribution policy
                $firefoxDistDirs = @(
                    "$env:ProgramFiles\Mozilla Firefox\distribution",
                    "$env:ProgramFiles(x86)\Mozilla Firefox\distribution"
                )
                
                $firefoxPolicies = @{
                    "policies" = @{
                        "DisableFirefoxAccounts"       = $true
                        "DisableFirefoxStudies"       = $true
                        "DisableForgetButton"         = $true
                        "DisablePocket"               = $true
                        "DisableProfileImport"        = $true
                        "DisableProfileRefresh"       = $true
                        "DisableSetDesktopBackground" = $true
                        "DisableSystemAddonUpdate"    = $true
                        "DisableTelemetry"            = $true
                        "NoDefaultBookmarks"          = $true
                        "OverrideFirstRunPage"        = ""
                        "OverridePostUpdatePage"      = ""
                        "DontCheckDefaultBrowser"     = $true
                        "DisableAppUpdate"            = $true
                        "UserMessaging" = @{
                            "WhatsNew"                = $false
                            "ExtensionRecommendations" = $false
                            "FeatureRecommendations"   = $false
                            "UrlbarInterventions"      = $false
                            "SkipOnboarding"           = $true
                        }
                        "Homepage" = @{
                            "URL"       = "about:blank"
                            "Locked"    = $false
                            "StartPage" = "none"
                        }
                        "DisableFeedbackCommands"    = $true
                        "DisablePrivateBrowsing"     = $false
                        "DisableBuiltinPDFViewer"    = $false
                    }
                } | ConvertTo-Json -Depth 5
                
                foreach ($distDir in $firefoxDistDirs) {
                    if (!(Test-Path $distDir)) {
                        New-Item -Path $distDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                    }
                    $firefoxPolicies | Out-File -FilePath (Join-Path $distDir "policies.json") -Encoding UTF8 -Force
                }
                
                # Firefox user.js configuration
                $firefoxProfileDirs = @(
                    "$env:APPDATA\Mozilla\Firefox\Profiles",
                    "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
                )
                
                $userJsContent = @'
// Disable first-run welcome screen and terms of use
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.rights.3.shown", true);
user_pref("browser.startup.homepage_override.buildID", "20100101");
user_pref("browser.aboutHomeSnippets.updateUrl", "");
user_pref("browser.startup.page", 0);
user_pref("browser.newtab.preload", false);
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtabpage.enhanced", false);
user_pref("browser.newtabpage.introShown", true);

// Suppress Firefox welcome screen and terms of use dialog
user_pref("browser.firstrun.show.localepicker", false);
user_pref("browser.firstrun.show.uidiscovery", false);
user_pref("datareporting.policy.firstRunURL", "");
user_pref("toolkit.startup.max_resumed_crashes", -1);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.rights.override", true);
user_pref("datareporting.policy.dataSubmissionPolicyNotifiedTime", "1000000000000000");
user_pref("datareporting.policy.dataSubmissionPolicyAcceptedVersion", 2);
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.firstRunTime", "1000000000000000");
user_pref("browser.bookmarks.restore_default_bookmarks", false);
user_pref("browser.disableResetPrompt", true);
user_pref("browser.onboarding.enabled", false);
user_pref("browser.laterrun.enabled", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
'@
                
                foreach ($profileDir in $firefoxProfileDirs) {
                    if (Test-Path $profileDir) {
                        $profiles = Get-ChildItem -Path $profileDir -Directory -ErrorAction SilentlyContinue
                        foreach ($profile in $profiles) {
                            $userJsContent | Out-File -FilePath (Join-Path $profile.FullName "user.js") -Encoding UTF8 -Force
                        }
                    }
                }
                
                Write-Host "Firefox first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Firefox first-run suppression" -ErrorRecord $_
            }
        }
        
        "brave" {
            try {
                # Brave Policy settings (Chromium-based)
                $bravePolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
                    "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"
                )
                
                foreach ($path in $bravePolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "NoFirstRun" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportBookmarks" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "ImportHistory" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                }
                
                Write-Host "Brave first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Brave first-run suppression" -ErrorRecord $_
            }
        }
        
        "opera" {
            try {
                # Opera Policy settings
                $operaPolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Opera Software\Opera",
                    "HKCU:\SOFTWARE\Policies\Opera Software\Opera"
                )
                
                foreach ($path in $operaPolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "AutoUpdateCheckPeriodMinutes" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
                }
                
                Write-Host "Opera first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Opera first-run suppression" -ErrorRecord $_
            }
        }
        
        "vivaldi" {
            try {
                # Vivaldi Policy settings (Chromium-based)
                $vivaldiPolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Vivaldi",
                    "HKCU:\SOFTWARE\Policies\Vivaldi"
                )
                
                foreach ($path in $vivaldiPolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "NoFirstRun" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
                }
                
                Write-Host "Vivaldi first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Vivaldi first-run suppression" -ErrorRecord $_
            }
        }
        
        "vscode" {
            try {
                # VS Code settings
                $vscodePolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\VSCode",
                    "HKCU:\SOFTWARE\Policies\Microsoft\VSCode"
                )
                
                foreach ($path in $vscodePolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "DisableWelcomePage" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DisableUpdateCheck" -Value 1 -Type DWord -Force
                }
                
                # Create VS Code user settings to suppress welcome
                $vscodeSettingsDir = "$env:APPDATA\Code\User"
                if (!(Test-Path $vscodeSettingsDir)) {
                    New-Item -Path $vscodeSettingsDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                }
                
                $vscodeSettings = @{
                    "workbench.welcome.enabled" = $false
                    "workbench.startupEditor" = "none"
                    "update.mode" = "none"
                    "extensions.autoCheckUpdates" = $false
                    "extensions.autoUpdate" = $false
                    "telemetry.enableTelemetry" = $false
                    "update.enableWindowsBackgroundUpdates" = $false
                } | ConvertTo-Json -Depth 3
                
                $vscodeSettings | Out-File -FilePath (Join-Path $vscodeSettingsDir "settings.json") -Encoding UTF8 -Force
                
                Write-Host "VS Code first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure VS Code first-run suppression" -ErrorRecord $_
            }
        }
        
        "vlc" {
            try {
                # VLC settings
                $vlcPath = "HKLM:\SOFTWARE\VideoLAN\VLC"
                if (Test-Path $vlcPath) {
                    Set-ItemProperty -Path $vlcPath -Name "IsFirstRun" -Value 0 -Type DWord -Force
                }
                
                # Create VLC config directory and preferences
                $vlcConfigDir = "$env:APPDATA\vlc"
                if (!(Test-Path $vlcConfigDir)) {
                    New-Item -Path $vlcConfigDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                }
                
                # Create vlcrc config file to suppress dialogs
                $vlcConfig = @'
[core] # core program
intf=qt
qt-privacy-ask=0
qt-updates-notif=0
qt-start-minimized=0
qt-notification=0
'@
                $vlcConfig | Out-File -FilePath (Join-Path $vlcConfigDir "vlcrc") -Encoding UTF8 -Force
                
                Write-Host "VLC first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure VLC first-run suppression" -ErrorRecord $_
            }
        }
        
        "adobereader" {
            try {
                # Adobe Reader settings
                $adobePaths = @(
                    "HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\AdobeViewer",
                    "HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\AdobeViewer",
                    "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader\DC\AdobeViewer"
                )
                
                foreach ($path in $adobePaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "EULA" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $path -Name "Launched" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                }
                
                Write-Host "Adobe Reader first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Adobe Reader first-run suppression" -ErrorRecord $_
            }
        }
        
        "notepadplusplus" {
            try {
                # Notepad++ settings
                $nppDirs = @(
                    "$env:ProgramFiles\Notepad++",
                    "$env:ProgramFiles(x86)\Notepad++"
                )
                
                foreach ($nppDir in $nppDirs) {
                    if (Test-Path $nppDir) {
                        $configPath = Join-Path $nppDir "config.xml"
                        $nppConfig = @'
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <GUIConfigs>
        <GUIConfig name="noUpdate">yes</GUIConfig>
        <GUIConfig name="Auto-detection">no</GUIConfig>
        <GUIConfig name="CheckHistoryFiles">no</GUIConfig>
        <GUIConfig name="EnableDoxygenComment">no</GUIConfig>
    </GUIConfigs>
</NotepadPlus>
'@
                        $nppConfig | Out-File -FilePath $configPath -Encoding UTF8 -Force
                    } 
                }
                
                Write-Host "Notepad++ first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Notepad++ first-run suppression" -ErrorRecord $_
            }
        }

        "chromium" {
            try {
                # Chromium policies
                $chromiumPolicyPaths = @(
                    "HKLM:\SOFTWARE\Policies\Chromium",
                    "HKCU:\SOFTWARE\Policies\Chromium"
                )
                foreach ($path in $chromiumPolicyPaths) {
                    Ensure-RegistryPath $path
                    Set-ItemProperty -Path $path -Name "NoFirstRun" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord -Force
                }
                
                # Chromium user default preferences
                $chrUserDirs = @(
                    "$env:LOCALAPPDATA\Chromium\User Data\Default",
                    "$env:APPDATA\Chromium\User Data\Default"
                )
                foreach ($dir in $chrUserDirs) {
                    if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
                    $prefs = @{
                        "profile" = @{ }
                        "browser" = @{ "check_default_browser" = $false }
                        "distribution" = @{ "skip_first_run_ui" = $true; "show_welcome_page" = $false }
                        "first_run_tabs" = @()
                    } | ConvertTo-Json -Depth 4
                    $prefs | Out-File -FilePath (Join-Path $dir "Preferences") -Encoding UTF8 -Force
                }
                Write-Host "Chromium first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Chromium first-run suppression" -ErrorRecord $_
            }
        }

        "tor" {
            try {
                # Tor Browser (Firefox-based) - write user.js in profile.default
                $torDirs = @(
                    "$env:ProgramFiles\Tor Browser",
                    "$env:ProgramFiles(x86)\Tor Browser",
                    "$env:LOCALAPPDATA\Tor Browser"
                )
                $userJs = @'
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.rights.3.shown", true);
user_pref("browser.startup.page", 0);
user_pref("browser.newtab.preload", false);
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtabpage.enhanced", false);
user_pref("browser.newtabpage.introShown", true);
user_pref("browser.firstrun.show.localepicker", false);
user_pref("browser.firstrun.show.uidiscovery", false);
user_pref("datareporting.policy.firstRunURL", "");
user_pref("toolkit.startup.max_resumed_crashes", -1);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.rights.override", true);
user_pref("datareporting.policy.dataSubmissionPolicyNotifiedTime", "1000000000000000");
user_pref("datareporting.policy.dataSubmissionPolicyAcceptedVersion", 2);
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.firstRunTime", "1000000000000000");
user_pref("browser.bookmarks.restore_default_bookmarks", false);
user_pref("browser.disableResetPrompt", true);
user_pref("browser.onboarding.enabled", false);
user_pref("browser.laterrun.enabled", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
'@
                foreach ($torDir in $torDirs) {
                    $profilePath = Join-Path $torDir "Browser\\TorBrowser\\Data\\Browser\\profile.default"
                    if (Test-Path $profilePath) {
                        $usrJsPath = Join-Path $profilePath "user.js"
                        $userJs | Out-File -FilePath $usrJsPath -Encoding UTF8 -Force
                    }
                }
                Write-Host "Tor Browser first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Tor first-run suppression" -ErrorRecord $_
            }
        }

        "wireshark" {
            try {
                $wsDir = "$env:APPDATA\Wireshark"
                if (!(Test-Path $wsDir)) { New-Item -Path $wsDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
                $prefsPath = Join-Path $wsDir "preferences"
                $prefsContent = @'
# Wireshark preferences
# Disable tip of the day and privilege warnings
gui.tip_of_the_day: FALSE
privs.warn_if_no_npcap: FALSE
'@
                $prefsContent | Out-File -FilePath $prefsPath -Encoding ASCII -Force
                Write-Host "Wireshark first-run suppression configured" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure Wireshark first-run suppression" -ErrorRecord $_
            }
        }

        "7zip" {
            try {
                # 7-Zip typically has no first-run dialogs; create optional config directory for completeness
                $sevenDir = "$env:APPDATA\7-Zip"
                if (!(Test-Path $sevenDir)) { New-Item -Path $sevenDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
                Write-Host "7-Zip first-run suppression (no action required)" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure 7-Zip first-run suppression" -ErrorRecord $_
            }
        }

        "putty" {
            try {
                # PuTTY typically has no first-run dialogs
                Write-Host "PuTTY first-run suppression (no action required)" -ForegroundColor Green
            } catch {
                Write-ErrorLog -FunctionName "Suppress-FirstRunExperiences" -ErrorMessage "Failed to configure PuTTY first-run suppression" -ErrorRecord $_
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
    # Note: autoUpgrade feature may not exist in all Chocolatey versions
    choco feature disable --name="autoUpgrade" --confirm 2>$null
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
            $null = choco install $package -y --ignore-checksums --no-progress --limit-output --no-autouninstaller
            $exit = $LASTEXITCODE
            if ($null -eq $exit) { $exit = 0 }
            
            # Treat reboot-required as success as per MSI conventions (0, 1641, 3010)
            if (@(0,1641,3010) -contains ([int]$exit)) {
                Write-Host "$package installation completed successfully (exit: $exit)" -ForegroundColor Green
                
                # Apply radical update prevention measures for each package
                Write-Host "Applying radical update prevention for $package..." -ForegroundColor Yellow
                Disable-ApplicationUpdates -PackageName $package
                
                # Apply first-run suppression immediately after installation
                Write-Host "Applying first-run suppression for $package..." -ForegroundColor Yellow
                try {
                    switch ($package.ToLower()) {
                        "googlechrome" { Suppress-FirstRunExperiences -ApplicationName "chrome" }
                        "microsoft-edge" { Suppress-FirstRunExperiences -ApplicationName "edge" }
                        "firefox" { Suppress-FirstRunExperiences -ApplicationName "firefox" }
                        "brave" { Suppress-FirstRunExperiences -ApplicationName "brave" }
                        "opera" { Suppress-FirstRunExperiences -ApplicationName "opera" }
                        "vivaldi" { Suppress-FirstRunExperiences -ApplicationName "vivaldi" }
                        "vscode" { Suppress-FirstRunExperiences -ApplicationName "vscode" }
                        "vlc" { Suppress-FirstRunExperiences -ApplicationName "vlc" }
                        "adobereader" { Suppress-FirstRunExperiences -ApplicationName "adobereader" }
                        "notepadplusplus" { Suppress-FirstRunExperiences -ApplicationName "notepadplusplus" }
                        "chromium" { Suppress-FirstRunExperiences -ApplicationName "chromium" }
                        "tor-browser" { Suppress-FirstRunExperiences -ApplicationName "tor" }
                        "wireshark" { Suppress-FirstRunExperiences -ApplicationName "wireshark" }
                        "7zip" { Suppress-FirstRunExperiences -ApplicationName "7zip" }
                        "putty" { Suppress-FirstRunExperiences -ApplicationName "putty" }
                    }
                } catch {
                    Write-Host "Warning: Could not apply first-run suppression for $package" -ForegroundColor Yellow
                }
            } else {
                $errorMsg = "Package installation completed with exit code: $exit"
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
        # Block known updater executables from outbound network access instead of using hostnames (unsupported)
        $blockPrograms = @(
            "C:\Program Files\Google\Update\GoogleUpdate.exe",
            "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
            "C:\Program Files\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            "C:\Program Files\Mozilla Firefox\updater.exe",
            "C:\Program Files (x86)\Mozilla Firefox\updater.exe",
            "C:\Program Files\Mozilla Firefox\maintenanceservice.exe",
            "C:\Program Files (x86)\Mozilla Firefox\maintenanceservice.exe"
        )
        foreach ($prog in $blockPrograms) {
            New-NetFirewallRule -DisplayName "Block Updater: $([System.IO.Path]::GetFileName($prog))" -Direction Outbound -Action Block -Program $prog -Profile Any -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host "Created firewall rules to block updater executables" -ForegroundColor Green
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
    
    # Apply first-run suppression for all installed applications
    Write-Host "Suppressing first-run experiences for installed applications..." -ForegroundColor Cyan
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
        Write-Host "Applying first-run suppression for $package..." -ForegroundColor Yellow
        try {
            switch ($package.ToLower()) {
                "googlechrome" { Suppress-FirstRunExperiences -ApplicationName "chrome" }
                "microsoft-edge" { Suppress-FirstRunExperiences -ApplicationName "edge" }
                "firefox" { Suppress-FirstRunExperiences -ApplicationName "firefox" }
                "brave" { Suppress-FirstRunExperiences -ApplicationName "brave" }
                "opera" { Suppress-FirstRunExperiences -ApplicationName "opera" }
                "vivaldi" { Suppress-FirstRunExperiences -ApplicationName "vivaldi" }
                "vscode" { Suppress-FirstRunExperiences -ApplicationName "vscode" }
                "vlc" { Suppress-FirstRunExperiences -ApplicationName "vlc" }
                "adobereader" { Suppress-FirstRunExperiences -ApplicationName "adobereader" }
                "notepadplusplus" { Suppress-FirstRunExperiences -ApplicationName "notepadplusplus" }
                "chromium" { Suppress-FirstRunExperiences -ApplicationName "chromium" }
                "tor-browser" { Suppress-FirstRunExperiences -ApplicationName "tor" }
                "wireshark" { Suppress-FirstRunExperiences -ApplicationName "wireshark" }
                "7zip" { Suppress-FirstRunExperiences -ApplicationName "7zip" }
                "putty" { Suppress-FirstRunExperiences -ApplicationName "putty" }
            }
        } catch {
            Write-Host "Warning: Could not apply first-run suppression for $package" -ForegroundColor Yellow
        }
    }
    Write-Host "First-run suppression completed for all applications" -ForegroundColor Green
    
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
        
        # Destroy update executables by replacing them with dummy
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
            # Ensure -Include works by using a wildcard path, restrict to files, and match against DirectoryName
            $updateFiles = Get-ChildItem -Path (Join-Path $drive "*") -Recurse -Include "*update*.exe","*upgrade*.exe","*autoupdate*.exe" -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.DirectoryName -notmatch "Guard|\\Windows(\\|$)|\\System32(\\|$)|\\WinSxS(\\|$)" }
            
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

#region VDI Background Optimization (Windows 11 24H2 LTSC/IoT)
Write-Host "Applying VDI background-usage minimization..." -ForegroundColor Cyan

try {
    # Policies to eliminate background activity, telemetry, and consumer experiences
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Type DWord -Force

    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -Type DWord -Force

    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Type DWord -Force  # Force deny

    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force

    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerFeatures" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlight" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord -Force

    # Windows Error Reporting off
    Ensure-RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Force
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Force

    # Disable SmartScreen for Explorer (keeps browser SmartScreen governed by its own policy)
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Off" -Type String -Force

    # Storage Sense off
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "AllowStorageSenseGlobal" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name "EnableStorageSenseGlobal" -Value 0 -Type DWord -Force

    # Disable automatic maintenance
    Ensure-RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1 -Type DWord -Force

    # Disable prefetchers
    Ensure-RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 -Type DWord -Force

    # Disable Location platform
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord -Force

    # OneDrive off (not present on LTSC typically, safe no-op)
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force

    # Turn off toast notifications system-wide
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord -Force

    # Browser background processes off (Chromium family)
    $chromePolicyPaths = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome",
        "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome",
        "HKCU:\SOFTWARE\Policies\Google\Chrome"
    )
    foreach ($p in $chromePolicyPaths) { Ensure-RegistryPath $p; Set-ItemProperty -Path $p -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force }

    $bravePolicyPaths = @(
        "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
        "HKCU:\SOFTWARE\Policies\BraveSoftware\Brave"
    )
    foreach ($p in $bravePolicyPaths) { Ensure-RegistryPath $p; Set-ItemProperty -Path $p -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force }

    $vivaldiPolicyPaths = @(
        "HKLM:\SOFTWARE\Policies\Vivaldi",
        "HKCU:\SOFTWARE\Policies\Vivaldi"
    )
    foreach ($p in $vivaldiPolicyPaths) { Ensure-RegistryPath $p; Set-ItemProperty -Path $p -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force }

    $edgePolicyPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
        "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    )
    foreach ($p in $edgePolicyPaths) { Ensure-RegistryPath $p; Set-ItemProperty -Path $p -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force; Set-ItemProperty -Path $p -Name "StartupBoostEnabled" -Value 0 -Type DWord -Force }

    # Disable hibernation and Windows memory compression / prelaunch
    try { powercfg /h off | Out-Null } catch {}
    try { Disable-MMAgent -ApplicationPreLaunch -ErrorAction SilentlyContinue } catch {}
    try { Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue } catch {}
    try { Disable-MMAgent -PageCombining -ErrorAction SilentlyContinue } catch {}

    # Aggressively disable non-essential services for VDI browser-only workloads
    $servicesToDisable = @(
        @{ Name="SysMain";            Display="SysMain (Superfetch)" },
        @{ Name="WSearch";            Display="Windows Search (Indexing)" },
        @{ Name="DiagTrack";          Display="Connected User Experiences and Telemetry" },
        @{ Name="dmwappushsvc";       Display="WAP Push (DMWAPPUSH)" },
        @{ Name="DoSvc";              Display="Delivery Optimization" },
        @{ Name="BITS";               Display="Background Intelligent Transfer Service" },
        @{ Name="Spooler";            Display="Print Spooler" },
        @{ Name="Fax";                Display="Fax" },
        @{ Name="WpnService";        Display="Windows Push Notifications System Service" },
        @{ Name="lfsvc";              Display="Geolocation Service" },
        @{ Name="RetailDemo";         Display="Retail Demo" },
        @{ Name="MapsBroker";         Display="Downloaded Maps Manager" },
        @{ Name="SharedAccess";       Display="Internet Connection Sharing (ICS)" },
        @{ Name="SSDPSRV";            Display="SSDP Discovery" },
        @{ Name="upnphost";           Display="UPnP Device Host" },
        @{ Name="RemoteRegistry";     Display="Remote Registry" },
        @{ Name="WbioSrvc";           Display="Windows Biometric Service" },
        @{ Name="bthserv";            Display="Bluetooth Support Service" },
        @{ Name="SEMgrSvc";           Display="Payments & NFC/SE Manager" },
        @{ Name="fhsvc";              Display="File History Service" },
        @{ Name="PcaSvc";             Display="Program Compatibility Assistant" },
        @{ Name="SCardSvr";           Display="Smart Card" },
        @{ Name="WerSvc";             Display="Windows Error Reporting" },
        @{ Name="wisvc";              Display="Windows Insider Service" },
        @{ Name="ClipSVC";            Display="Client License Service (ClipSVC)" },
        @{ Name="LicenseManager";     Display="Windows License Manager" },
        @{ Name="TimeBrokerSvc";      Display="Time Broker (UWP background)" },
        @{ Name="WMPNetworkSvc";      Display="WMP Network Sharing" }
    )
    foreach ($svc in $servicesToDisable) {
        Disable-ServiceSafely -ServiceName $svc.Name -DisplayName $svc.Display -NoStopOnError
    }

    # Per-user services often auto-provision with suffixes (e.g., *_1234). Attempt to disable them as well.
    $perUserPatterns = @("CDPUserSvc_*","OneSyncSvc_*","WpnUserService_*","BluetoothUserService_*","PimIndexMaintenanceSvc_*","UserDataSvc_*","cbdhsvc_*","PrintWorkflowUserSvc_*")
    foreach ($pattern in $perUserPatterns) {
        Get-Service -Name $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Disable-ServiceSafely -ServiceName $_.Name -DisplayName $_.DisplayName -NoStopOnError
        }
    }
    # Also set base definitions to Disabled so new instances don't spawn
    $perUserBases = @("CDPUserSvc","OneSyncSvc","WpnUserService","BluetoothUserService","PimIndexMaintenanceSvc","UserDataSvc","cbdhsvc","PrintWorkflowUserSvc")
    foreach ($base in $perUserBases) {
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$base"
        if (Test-Path $svcKey) {
            try { Set-ItemProperty -Path $svcKey -Name Start -Value 4 -Type DWord -Force } catch {}
        }
    }

    # Defender (best-effort minimize realtime impact; may be governed by tamper protection)
    try {
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -Force
        # Try to turn off realtime scanning now
        try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch {}
        Disable-ServiceSafely -ServiceName "WinDefend" -DisplayName "Microsoft Defender Antivirus" -NoStopOnError
        Disable-ServiceSafely -ServiceName "WdNisSvc" -DisplayName "Microsoft Defender Antivirus Network Inspection Service" -NoStopOnError
        Disable-ServiceSafely -ServiceName "SecurityHealthService" -DisplayName "Windows Security Center" -NoStopOnError
        Disable-ServiceSafely -ServiceName "Sense" -DisplayName "Microsoft Defender for Endpoint Service" -NoStopOnError
    } catch {}

    Write-Host "VDI background-usage minimization applied" -ForegroundColor Green
}
catch {
    Write-ErrorLog -FunctionName "VDI-Optimization" -ErrorMessage ("Failed to apply VDI background minimization: " + $_.Exception.Message) -ErrorRecord $_
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

# Prefer local guardsrv.exe next to this script; fallback to GitHub download
$guardUrl  = "https://raw.githubusercontent.com/saschazesiger/guarddownload-sl52610lmu7ayhb56tacs/main/guardsrv.exe"
$guardDest = "$guardDir\guardsrv.exe"

try {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $workingDir = Get-Location | Select-Object -ExpandProperty Path
    
    $localCandidates = @()
    if ($scriptDir) {
        $localCandidates += (Join-Path $scriptDir 'guardsrv.exe')
    }
    $localCandidates += (Join-Path $workingDir 'guardsrv.exe')
    
    $copied = $false
    foreach ($candidate in $localCandidates) {
        if ($candidate -and (Test-Path $candidate)) {
            Write-Host "Found local guardsrv.exe at $candidate - copying..." -ForegroundColor Cyan
            Copy-Item -Path $candidate -Destination $guardDest -Force -ErrorAction Stop
            $copied = $true
            break
        }
    }

    if (-not $copied) {
        Write-Host "Downloading guardsrv.exe from $guardUrl..." -ForegroundColor Cyan
        Write-Host "Target location: $guardDest" -ForegroundColor Cyan
        Invoke-WebRequest -Uri $guardUrl -OutFile $guardDest -UseBasicParsing -ErrorAction Stop
        Write-Host "Downloaded guardsrv.exe" -ForegroundColor Green
    } else {
        Write-Host "guardsrv.exe copied to $guardDest" -ForegroundColor Green
    }
}
catch {
    Write-ErrorLog -FunctionName "InstallGuardSoftware" -ErrorMessage "Failed to stage guardsrv.exe to $guardDest" -ErrorRecord $_
}
#endregion

#region Configure Auto Login
Write-Host "Setting up auto login..." -ForegroundColor Cyan

try {
    # Registry path for auto login
    $winLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    
    # Set auto login parameters to match autounattend.xml configuration
    # The autounattend.xml creates a user "User" (display name "GuardAccount") and enables auto login for Administrator
    # We need to configure auto login for the actual user created by autounattend.xml
    Set-ItemProperty -Path $winLogonPath -Name "AutoAdminLogon" -Value "1" -Type String -Force
    Set-ItemProperty -Path $winLogonPath -Name "DefaultUserName" -Value "User" -Type String -Force
    Set-ItemProperty -Path $winLogonPath -Name "DefaultPassword" -Value "GuardUser5046!" -Type String -Force
    Set-ItemProperty -Path $winLogonPath -Name "DefaultDomainName" -Value "." -Type String -Force
    
    # Ensure auto login count is not limited (remove count limit set by autounattend.xml)
    Remove-ItemProperty -Path $winLogonPath -Name "AutoLogonCount" -ErrorAction SilentlyContinue
    
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

# Define the XML content directly in the script - configured for hidden background execution with GUI access
$taskXmlContent = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-12-13T12:57:55.7234893</Date>
    <Author>User</Author>
    <URI>\GuardMonitor</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>User</UserId>
      <LogonType>InteractiveToken</LogonType>
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
    <Priority>4</Priority>
    <RestartOnFailure>
      <Count>10</Count>
      <Interval>PT1M</Interval>
    </RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable>
    <WakeToRun>false</WakeToRun>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT0S</Delay>
      <UserId>User</UserId>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\ProgramData\Guard.ch\guardsrv.exe</Command>
      <WorkingDirectory>C:\ProgramData\Guard.ch</WorkingDirectory>
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
        Write-Host "GuardMonitor task created successfully from embedded XML" -ForegroundColor Green            } else {
                Write-Host "Failed to verify task creation. Output: $result" -ForegroundColor Yellow
            }
}
catch {
    Write-ErrorLog -FunctionName "CreateGuardMonitorTask" -ErrorMessage "Error creating GuardMonitor scheduled task from embedded XML" -ErrorRecord $_

    # Fallback: Try to create the task with PowerShell commands
    try {
        $action = New-ScheduledTaskAction -Execute "C:\ProgramData\Guard.ch\guardsrv.exe" -WorkingDirectory "C:\ProgramData\Guard.ch"
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "User"
        # Remove unsupported parameters (-Priority, -RunOnlyIfLoggedOn) and use a valid ExecutionTimeLimit
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden -MultipleInstances IgnoreNew -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
        $principal = New-ScheduledTaskPrincipal -UserId "User" -LogonType Interactive -RunLevel Highest
        
        Register-ScheduledTask -TaskName "GuardMonitor" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop
        Write-Host "GuardMonitor task created with PowerShell commands as fallback" -ForegroundColor Green
    }
    catch {
        Write-ErrorLog -FunctionName "CreateGuardMonitorTaskFallback" -ErrorMessage "Error creating GuardMonitor task with PowerShell commands" -ErrorRecord $_
    }
}
#endregion

#region Add Registry Autorun Entry as Backup
Write-Host "Adding registry autorun entry as backup..." -ForegroundColor Cyan

try {
    # Add to current user's autorun (HKCU) for GUI access
    $autorunPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $autorunPath -Name "GuardMonitor" -Value "C:\ProgramData\Guard.ch\guardsrv.exe" -Type String -Force
    
    # Also add to all users autorun (HKLM) as secondary backup
    $autorunPathAll = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $autorunPathAll -Name "GuardMonitor" -Value "C:\ProgramData\Guard.ch\guardsrv.exe" -Type String -Force
    
    Write-Host "Registry autorun entries created successfully" -ForegroundColor Green
}
catch {
    Write-ErrorLog -FunctionName "CreateAutorunEntry" -ErrorMessage "Error creating registry autorun entry" -ErrorRecord $_
}
#endregion

#region Create User Startup Script
Write-Host "Creating user startup script..." -ForegroundColor Cyan

try {
    # Create startup folder if it doesn't exist
    $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (!(Test-Path $startupFolder)) {
        New-Item -Path $startupFolder -ItemType Directory -Force | Out-Null
    }
    
    # Create a batch file in startup folder for immediate hidden GUI context execution
    $startupBatchContent = @'
@echo off
:: Run guardsrv.exe hidden in background with GUI access
cd /d "C:\ProgramData\Guard.ch"
if exist "guardsrv.exe" (
    start /min "" "guardsrv.exe" > nul 2>&1
)
exit /b 0
'@
    
    $startupBatchPath = "$startupFolder\GuardMonitor.bat"
    $startupBatchContent | Out-File -FilePath $startupBatchPath -Encoding ASCII -Force
    
    Write-Host "User startup script created at: $startupBatchPath" -ForegroundColor Green
}
catch {
    Write-ErrorLog -FunctionName "CreateStartupScript" -ErrorMessage "Error creating user startup script" -ErrorRecord $_
}
#endregion

#region Pin browsers to taskbar
Write-Host "Pinning browsers to the taskbar..." -ForegroundColor Cyan

function Get-BrowserTaskbarLinkPaths {
    [OutputType([string[]])]
    param()

    $patterns = @(
        '*Microsoft Edge.lnk',
        '*Google Chrome.lnk',
        '*Mozilla Firefox.lnk',
        '*Firefox.lnk',
        '*Brave*.lnk',
        '*Opera*.lnk',
        '*Vivaldi*.lnk',
        '*Chromium*.lnk'
    )

    $paths = @()
    $startMenuDirs = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    )

    foreach ($dir in $startMenuDirs) {
        if (Test-Path $dir) {
            foreach ($pat in $patterns) {
                try {
                    $found = Get-ChildItem -Path $dir -Filter $pat -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -ErrorAction SilentlyContinue
                    if ($found) { $paths += $found }
                } catch {}
            }
        }
    }

    # Deduplicate preserving order
    $hash = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unique = @()
    foreach ($p in $paths) { if ($hash.Add($p)) { $unique += $p } }

    if (-not $unique -or $unique.Count -eq 0) { return @() }

    # Opinionated ordering: Edge, Chrome, Firefox, Brave, Opera, Vivaldi, Chromium
    $ordered = $unique | Sort-Object {
        $n = $_.ToLower()
        if     ($n -match 'edge')     { 10 }
        elseif ($n -match 'google' -or ($n -match 'chrome' -and $n -notmatch 'chromium')) { 20 }
        elseif ($n -match 'firefox')  { 30 }
        elseif ($n -match 'brave')    { 40 }
        elseif ($n -match 'opera')    { 50 }
        elseif ($n -match 'vivaldi')  { 60 }
        elseif ($n -match 'chromium') { 70 }
        else { 999 }
    }

    return $ordered
}

function Write-TaskbarLayoutXml {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string[]]$LinkPaths,
        [Parameter(Mandatory=$true)][string]$Destination
    )

    if (-not $LinkPaths -or $LinkPaths.Count -eq 0) { return $false }

    $xmlHeader = '<?xml version="1.0" encoding="utf-8"?>'
    $xmlStart  = '<TaskbarLayout><TaskbarPinList>'
    $xmlEnd    = '</TaskbarPinList></TaskbarLayout>'

    $items = foreach ($lp in $LinkPaths) {
        $safe = $lp.Replace('&','&amp;').Replace('"','&quot;')
        # Use string formatting to avoid potential parsing issues
        "  <DesktopApp DesktopApplicationLinkPath=`"$safe`"/>"
    }

    $content = $xmlHeader + "`r`n" + $xmlStart + "`r`n" + ($items -join "`r`n") + "`r`n" + $xmlEnd + "`r`n"

    $destDir = Split-Path -Path $Destination -Parent
    if (!(Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }

    $content | Out-File -FilePath $Destination -Encoding utf8 -Force
    return $true
}

try {
    $browserLinks = Get-BrowserTaskbarLinkPaths
    if ($browserLinks -and $browserLinks.Count -gt 0) {
        $currentUserXml = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Shell\TaskbarLayoutModification.xml'
        $defaultUserXml = 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\TaskbarLayoutModification.xml'

        $okCurrent = Write-TaskbarLayoutXml -LinkPaths $browserLinks -Destination $currentUserXml
        $okDefault = Write-TaskbarLayoutXml -LinkPaths $browserLinks -Destination $defaultUserXml

        Write-Host ("Taskbar layout written. Current user: {0}, Default profile: {1}" -f $okCurrent, $okDefault) -ForegroundColor Green

        # Try to restart Explorer (reboot is also scheduled later)
        try { Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue } catch {}
    }
    else {
        Write-Host "No browser shortcuts found to pin" -ForegroundColor Yellow
    }
}
catch {
    Write-ErrorLog -FunctionName "TaskbarPinning" -ErrorMessage ("Failed to pin browsers to the taskbar: " + $_.Exception.Message) -ErrorRecord $_
}
#endregion

#region Schedule Reboot
Write-Host "Scheduling a reboot in 5 minutes..." -ForegroundColor Cyan
try {
    # Schedule restart in 300 seconds (5 minutes)
    shutdown.exe /r /t 300 /c "Guard install finished. System will reboot in 5 minutes." /d p:4:1
    Write-Host "Reboot scheduled. Run 'shutdown /a' to cancel if needed." -ForegroundColor Yellow
} catch {
    Write-ErrorLog -FunctionName "ScheduleReboot" -ErrorMessage "Failed to schedule reboot" -ErrorRecord $_
}

# Stop transcript logging
try { Stop-Transcript | Out-Null } catch {}
#endregion