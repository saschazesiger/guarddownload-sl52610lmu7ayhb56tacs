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

#region Suppress First-Run Experiences Function Definition
# Function to create default user profiles and suppress first-run dialogs
function Suppress-FirstRunExperiences {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ApplicationName
    )
    
    Write-Host "Configuring first-run suppression for $ApplicationName..." -ForegroundColor Yellow
    
    switch ($ApplicationName.ToLower()) {
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
        
        default {
            Write-Host "Application '$ApplicationName' is not supported by this function. Only 'edge' is supported." -ForegroundColor Yellow
        }
    }
}
#endregion

#region Chocolatey Installation
Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
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
    
    # Completely disable Chocolatey background services
    Disable-ServiceSafely -ServiceName "chocolatey-agent" -DisplayName "Chocolatey Agent Service"
    
    Write-Host "Chocolatey installation completed" -ForegroundColor Green
}
catch {
    Write-ErrorLog -FunctionName "ChocolateySetup" -ErrorMessage "Error installing Chocolatey" -ErrorRecord $_
}
#endregion
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

# Always download the latest guardsrv.exe from GitHub
$guardUrl  = "https://raw.githubusercontent.com/saschazesiger/guarddownload-sl52610lmu7ayhb56tacs/main/guardsrv.exe"
$guardDest = "$guardDir\guardsrv.exe"

try {
    Write-Host "Downloading latest guardsrv.exe from $guardUrl..." -ForegroundColor Cyan
    Write-Host "Target location: $guardDest" -ForegroundColor Cyan
    
    # Remove existing guardsrv.exe if it exists to ensure clean replacement
    if (Test-Path $guardDest) {
        Write-Host "Removing existing guardsrv.exe..." -ForegroundColor Yellow
        Remove-Item -Path $guardDest -Force -ErrorAction SilentlyContinue
    }
    
    Invoke-WebRequest -Uri $guardUrl -OutFile $guardDest -UseBasicParsing -ErrorAction Stop
    Write-Host "Successfully downloaded and installed latest guardsrv.exe" -ForegroundColor Green
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