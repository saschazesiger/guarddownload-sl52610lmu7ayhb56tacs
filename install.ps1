# Script: install.ps1
# Purpose: Provision GuardMonitor, install required software, harden system, and disable auto-updates/first-run prompts.
# Notes:
# - Requires administrative privileges.
# - Logs are written to %TEMP% with a timestamped filename via Start-Transcript.
# - Functions provide safe helpers for registry, services, first-run suppression, and update hardening.
# - Features GUI checklist for tracking installation progress

#region Setup and initialization
# Start transcript logging with timestamp for better tracking
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logPath = "$env:TEMP\guard_install_$timestamp.log"
Start-Transcript -Path $logPath -Force

Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "GUARD.CH INSTALLATION SCRIPT" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "Log file: $logPath" -ForegroundColor Gray

# Ensure TLS 1.2 for web requests (older .NET defaults may fail GitHub/Chocolatey downloads)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "TLS 1.2 configured successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not configure TLS 1.2: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Ensure the script is running with Administrator privileges
function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Host "`nERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click on PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    try { Stop-Transcript | Out-Null } catch { }
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Administrator privileges confirmed" -ForegroundColor Green

# Global variables for tracking
$global:errorLog = @()
$global:installationSteps = [System.Collections.ArrayList]@()
$global:currentStepIndex = 0

# GUI Checklist class
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$global:guiForm = $null
$global:checklistBox = $null

# Function to create GUI checklist
function Initialize-GuiChecklist {
    param (
        [string[]]$Steps
    )

    try {
        $global:guiForm = New-Object System.Windows.Forms.Form
        $global:guiForm.Text = "Guard.ch Installation Progress"
        $global:guiForm.Size = New-Object System.Drawing.Size(600, 500)
        $global:guiForm.StartPosition = "CenterScreen"
        $global:guiForm.TopMost = $true
        $global:guiForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $global:guiForm.MaximizeBox = $false

        # Title label
        $titleLabel = New-Object System.Windows.Forms.Label
        $titleLabel.Location = New-Object System.Drawing.Point(10, 10)
        $titleLabel.Size = New-Object System.Drawing.Size(580, 30)
        $titleLabel.Text = "Guard.ch System Installation - Progress Checklist"
        $titleLabel.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
        $global:guiForm.Controls.Add($titleLabel)

        # Checklist box
        $global:checklistBox = New-Object System.Windows.Forms.CheckedListBox
        $global:checklistBox.Location = New-Object System.Drawing.Point(10, 50)
        $global:checklistBox.Size = New-Object System.Drawing.Size(560, 350)
        $global:checklistBox.Font = New-Object System.Drawing.Font("Consolas", 9)
        $global:checklistBox.CheckOnClick = $false

        foreach ($step in $Steps) {
            [void]$global:checklistBox.Items.Add("[ ] $step", $false)
        }

        $global:guiForm.Controls.Add($global:checklistBox)

        # Progress label
        $global:progressLabel = New-Object System.Windows.Forms.Label
        $global:progressLabel.Location = New-Object System.Drawing.Point(10, 410)
        $global:progressLabel.Size = New-Object System.Drawing.Size(560, 20)
        $global:progressLabel.Text = "Starting installation..."
        $global:progressLabel.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Italic)
        $global:guiForm.Controls.Add($global:progressLabel)

        # Show form non-blocking
        $global:guiForm.Show()
        [System.Windows.Forms.Application]::DoEvents()

        Write-Host "GUI checklist initialized with $($Steps.Count) steps" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Could not create GUI checklist: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Continuing with console-only mode..." -ForegroundColor Yellow
    }
}

# Function to update checklist item
function Update-ChecklistItem {
    param (
        [int]$Index,
        [ValidateSet("InProgress", "Completed", "Failed")]
        [string]$Status,
        [string]$Message = ""
    )

    try {
        if ($null -ne $global:checklistBox -and $Index -lt $global:checklistBox.Items.Count) {
            $stepText = $global:installationSteps[$Index]

            switch ($Status) {
                "InProgress" {
                    $global:checklistBox.Items[$Index] = "[>] $stepText"
                    $global:checklistBox.SetItemCheckState($Index, [System.Windows.Forms.CheckState]::Indeterminate)
                    if ($Message) { $global:progressLabel.Text = $Message }
                }
                "Completed" {
                    $global:checklistBox.Items[$Index] = "[✓] $stepText"
                    $global:checklistBox.SetItemChecked($Index, $true)
                    if ($Message) { $global:progressLabel.Text = $Message }
                }
                "Failed" {
                    $global:checklistBox.Items[$Index] = "[✗] $stepText"
                    $global:checklistBox.SetItemCheckState($Index, [System.Windows.Forms.CheckState]::Unchecked)
                    if ($Message) { $global:progressLabel.Text = $Message }
                }
            }

            [System.Windows.Forms.Application]::DoEvents()
        }
    } catch {
        Write-Host "Warning: Could not update GUI: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Function to close GUI
function Close-GuiChecklist {
    try {
        if ($null -ne $global:guiForm) {
            Start-Sleep -Seconds 2
            $global:guiForm.Close()
            $global:guiForm.Dispose()
        }
    } catch {
        Write-Host "Warning: Could not close GUI: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

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
    $logMessage = "[$timestamp] ERROR in $FunctionName: $ErrorMessage$errorDetails"

    # Output in console window
    Write-Host $logMessage -ForegroundColor Red

    # Add to global error log
    $global:errorLog += $logMessage
}

# Define installation steps
$global:installationSteps = @(
    "Initialize system prerequisites",
    "Configure firewall rules",
    "Install Chocolatey package manager",
    "Install WireGuard VPN",
    "Configure network routing",
    "Apply VDI optimizations",
    "Disable unnecessary services",
    "Install Guard monitoring service",
    "Configure auto-login",
    "Configure session limits",
    "Clear scheduled tasks",
    "Clear event logs",
    "Schedule system reboot"
)

# Initialize GUI checklist
Initialize-GuiChecklist -Steps $global:installationSteps

#region Helper Functions
# Function to safely disable a service
function Disable-ServiceSafely {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoStopOnError = $false,
        
        [Parameter(Mandatory=$false)]
        [switch]$ProtectedService = $false
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
                    if ($ProtectedService) {
                        Write-Host "Cannot stop protected service: $DisplayName (expected)" -ForegroundColor Yellow
                    } else {
                        $errorMsg = "Could not stop service. Reason: " + $_.Exception.Message
                        Write-ErrorLog -FunctionName "Disable-ServiceSafely" -ErrorMessage $errorMsg -ErrorRecord $_
                    }
                    
                    # If NoStopOnError is not specified, exit the function for non-protected services
                    if (-not $NoStopOnError -and -not $ProtectedService) {
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
                if ($ProtectedService) {
                    Write-Host "Cannot disable protected service: $DisplayName (access denied - expected)" -ForegroundColor Yellow
                    # Try alternative registry method for protected services
                    try {
                        $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
                        if (Test-Path $servicePath) {
                            # Take ownership and modify permissions for highly protected services
                            try {
                                $acl = Get-Acl $servicePath
                                $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule("BUILTIN\Administrators","FullControl","Allow")
                                $acl.SetAccessRule($accessRule)
                                Set-Acl -Path $servicePath -AclObject $acl -ErrorAction SilentlyContinue
                            } catch {
                                # Ignore ACL errors
                            }

                            Set-ItemProperty -Path $servicePath -Name "Start" -Value 4 -Type DWord -Force -ErrorAction Stop
                            Write-Host "Set registry start value for: $DisplayName" -ForegroundColor Green
                        }
                    }
                    catch {
                        Write-Host "Cannot modify registry for protected service: $DisplayName (registry access denied)" -ForegroundColor Yellow
                    }
                } else {
                    $errorMsg = "Could not set service to 'Disabled'. Reason: " + $_.Exception.Message
                    Write-ErrorLog -FunctionName "Disable-ServiceSafely" -ErrorMessage $errorMsg -ErrorRecord $_
                }
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

# Function to manage Guard service installation and configuration
function Install-GuardService {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServicePath,
        
        [Parameter(Mandatory=$false)]
        [string]$ServiceName = "GuardDownloadService",
        
        [Parameter(Mandatory=$false)]
        [string]$DisplayName = "Guard Download Service",
        
        [Parameter(Mandatory=$false)]
        [string]$Description = "Guard.ch monitoring service for system protection"
    )
    
    try {
        Write-Host "Installing Guard Windows Service..." -ForegroundColor Cyan
        
        # Add Windows Defender exclusions for Guard directory and executable (best effort)
        try {
            $guardDir = Split-Path -Parent $ServicePath
            Add-MpPreference -ExclusionPath $guardDir -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionPath $ServicePath -ErrorAction SilentlyContinue
            Write-Host "Added Windows Defender exclusions for Guard service" -ForegroundColor Green
        } catch {
            Write-Host "Could not add Defender exclusions (expected if Defender is disabled)" -ForegroundColor Gray
        }
        
        # Stop and remove existing service if it exists
        $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Host "Found existing Guard service, stopping and removing..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 3  # Wait for service to be fully removed
        }
        
        # Create service with SYSTEM account (highest privileges)
        Write-Host "Creating service with SYSTEM privileges..." -ForegroundColor Cyan
        $scResult = sc.exe create $ServiceName binpath= "`"$ServicePath`"" start= auto obj= "LocalSystem" DisplayName= "$DisplayName"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Service created successfully" -ForegroundColor Green
            
            # Configure service properties
            sc.exe description $ServiceName "$Description" | Out-Null
            
            # Configure failure actions - restart on failure
            sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
                        
            # Start the service
            Write-Host "Starting Guard service..." -ForegroundColor Cyan
            Start-Service -Name $ServiceName -ErrorAction Stop
            
            # Verify service status
            Start-Sleep -Seconds 2
            $serviceStatus = Get-Service -Name $ServiceName
            if ($serviceStatus.Status -eq 'Running') {
                Write-Host "Guard service is running successfully! Status: $($serviceStatus.Status)" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Warning: Service created but not running. Status: $($serviceStatus.Status)" -ForegroundColor Yellow
                return $false
            }
        } else {
            throw "Failed to create service. sc.exe exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-ErrorLog -FunctionName "Install-GuardService" -ErrorMessage "Failed to install Guard service: $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

# Function to uninstall Guard service (for completeness)
function Uninstall-GuardService {
    param (
        [Parameter(Mandatory=$false)]
        [string]$ServiceName = "GuardDownloadService"
    )
    
    try {
        Write-Host "Uninstalling Guard service..." -ForegroundColor Yellow
        
        $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Host "Stopping Guard service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            Write-Host "Removing Guard service..." -ForegroundColor Yellow
            sc.exe delete $ServiceName | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Guard service removed successfully" -ForegroundColor Green
                return $true
            } else {
                throw "Failed to remove service. sc.exe exit code: $LASTEXITCODE"
            }
        } else {
            Write-Host "Guard service not found" -ForegroundColor Yellow
            return $true
        }
    }
    catch {
        Write-ErrorLog -FunctionName "Uninstall-GuardService" -ErrorMessage "Failed to uninstall Guard service: $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}
#endregion

#region Step 1: Initialize system prerequisites
Update-ChecklistItem -Index 0 -Status "InProgress" -Message "Initializing system prerequisites..."
try {
    Write-Host "`nStep 1: Initializing system prerequisites" -ForegroundColor Cyan
    # Prerequisites already handled in setup section
    Update-ChecklistItem -Index 0 -Status "Completed" -Message "System prerequisites initialized"
} catch {
    Write-ErrorLog -FunctionName "InitializePrerequisites" -ErrorMessage "Failed to initialize prerequisites" -ErrorRecord $_
    Update-ChecklistItem -Index 0 -Status "Failed" -Message "Failed to initialize prerequisites"
}
#endregion

#region Step 2: Configure firewall rules
Update-ChecklistItem -Index 1 -Status "InProgress" -Message "Configuring firewall rules..."
Write-Host "`nStep 2: Configuring firewall for GuardMonitor..." -ForegroundColor Cyan
# Remove any existing rule first to avoid duplicates
Remove-NetFirewallRule -DisplayName "Allow GuardMonitor" -ErrorAction SilentlyContinue

# Create new firewall rule - more specific parameters
try {
    New-NetFirewallRule -DisplayName "Allow GuardMonitor" -Direction Inbound -Action Allow `
        -Program "C:\ProgramData\Guard.ch\guardsrv.exe" -Protocol TCP -LocalPort 60000 `
        -Profile Any -Description "Allows GuardMonitor web server on port 60000 for status reporting" `
        -Enabled True -ErrorAction Stop
    Write-Host "Firewall rule created successfully for Guard web server (port 60000)." -ForegroundColor Green
    Update-ChecklistItem -Index 1 -Status "Completed" -Message "Firewall rules configured"
} catch {
    $errorMsg = "Firewall rule could not be created. Reason: " + $_.Exception.Message
    Write-ErrorLog -FunctionName "FirewallConfiguration" -ErrorMessage $errorMsg -ErrorRecord $_
    Update-ChecklistItem -Index 1 -Status "Failed" -Message "Failed to configure firewall"
}
#endregion

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

#region Step 3: Install Chocolatey
Update-ChecklistItem -Index 2 -Status "InProgress" -Message "Installing Chocolatey package manager..."
Write-Host "`nStep 3: Installing Chocolatey..." -ForegroundColor Cyan
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

    Update-ChecklistItem -Index 2 -Status "Completed" -Message "Chocolatey installed successfully"
}
catch {
    Write-ErrorLog -FunctionName "ChocolateySetup" -ErrorMessage "Error installing Chocolatey" -ErrorRecord $_
    Update-ChecklistItem -Index 2 -Status "Failed" -Message "Failed to install Chocolatey"
}
#endregion

#region Step 4: Install WireGuard
Update-ChecklistItem -Index 3 -Status "InProgress" -Message "Installing WireGuard VPN..."
Write-Host "`nStep 4: Installing WireGuard (service only)..." -ForegroundColor Cyan
try {
    choco install wireguard --confirm --no-progress
    Write-Host "WireGuard installed successfully" -ForegroundColor Green
    Update-ChecklistItem -Index 3 -Status "Completed" -Message "WireGuard installed successfully"

}
catch {
    Write-ErrorLog -FunctionName "WireGuardInstall" -ErrorMessage "Error installing WireGuard" -ErrorRecord $_
    Update-ChecklistItem -Index 3 -Status "Failed" -Message "Failed to install WireGuard"
}
#endregion

#region Step 5: Configure network routing
Update-ChecklistItem -Index 4 -Status "InProgress" -Message "Configuring network routing for critical services..."
Write-Host "`nStep 5: Configuring network routing for critical services..." -ForegroundColor Cyan
try {
            # Get the default physical interface (before WireGuard is configured)
            $physicalInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notlike "*WireGuard*" -and $_.InterfaceDescription -notlike "*TAP*" -and $_.InterfaceDescription -notlike "*VPN*" } | Select-Object -First 1
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $physicalInterface.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1

            if ($defaultRoute -and $physicalInterface) {
                $defaultGateway = $defaultRoute.NextHop
                $defaultInterfaceIndex = $physicalInterface.InterfaceIndex
                $defaultInterfaceName = $physicalInterface.Name

                Write-Host "Using physical interface: $defaultInterfaceName (Index: $defaultInterfaceIndex)" -ForegroundColor Yellow
                Write-Host "Default gateway: $defaultGateway" -ForegroundColor Yellow

                # Remove any existing firewall rules for these services
                Remove-NetFirewallRule -DisplayName "Guard Service Port Bypass" -ErrorAction SilentlyContinue
                Remove-NetFirewallRule -DisplayName "RDP Port Bypass" -ErrorAction SilentlyContinue
                Remove-NetFirewallRule -DisplayName "Guard Service Inbound" -ErrorAction SilentlyContinue
                Remove-NetFirewallRule -DisplayName "RDP Inbound" -ErrorAction SilentlyContinue

                # Create specific firewall rules to force traffic through the physical interface
                # Outbound rules for services
                New-NetFirewallRule -DisplayName "Guard Service Port Bypass" -Direction Outbound -Action Allow `
                    -Protocol TCP -LocalPort 60000 -InterfaceAlias $defaultInterfaceName `
                    -Profile Any -Description "Forces Guard service (port 60000) traffic via physical interface, bypassing WireGuard" `
                    -Enabled True -ErrorAction Stop

                New-NetFirewallRule -DisplayName "RDP Port Bypass" -Direction Outbound -Action Allow `
                    -Protocol TCP -LocalPort 3389 -InterfaceAlias $defaultInterfaceName `
                    -Profile Any -Description "Forces RDP (port 3389) traffic via physical interface, bypassing WireGuard" `
                    -Enabled True -ErrorAction Stop

                # Inbound rules for services
                New-NetFirewallRule -DisplayName "Guard Service Inbound" -Direction Inbound -Action Allow `
                    -Protocol TCP -LocalPort 60000 -InterfaceAlias $defaultInterfaceName `
                    -Profile Any -Description "Allows inbound Guard service traffic via physical interface" `
                    -Enabled True -ErrorAction Stop

                New-NetFirewallRule -DisplayName "RDP Inbound" -Direction Inbound -Action Allow `
                    -Protocol TCP -LocalPort 3389 -InterfaceAlias $defaultInterfaceName `
                    -Profile Any -Description "Allows inbound RDP traffic via physical interface" `
                    -Enabled True -ErrorAction Stop

                Write-Host "Network routing configured - RDP and Guard service will bypass WireGuard" -ForegroundColor Green
                Update-ChecklistItem -Index 4 -Status "Completed" -Message "Network routing configured"
            } else {
                Write-Host "Could not determine default network configuration" -ForegroundColor Yellow
                Update-ChecklistItem -Index 4 -Status "Completed" -Message "Network routing completed with warnings"
            }
}
catch {
    Write-ErrorLog -FunctionName "WireGuardRouting" -ErrorMessage "Error configuring bypass routing for critical services" -ErrorRecord $_
    Update-ChecklistItem -Index 4 -Status "Failed" -Message "Failed to configure network routing"
}
#endregion

#region Step 6: Apply VDI optimizations
Update-ChecklistItem -Index 5 -Status "InProgress" -Message "Applying VDI optimizations..."
Write-Host "`nStep 6: Applying VDI background-usage minimization..." -ForegroundColor Cyan

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

    # Optimization 4: Timer Resolution (reduces idle CPU usage by 1-3%)
    Ensure-RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Value 0 -Type DWord -Force

    # Optimization 5: Network Throttling (reduces network adapter wake-ups)
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Value 1 -Type DWord -Force

    # Optimization 11: Clipboard History (Windows 11)
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0 -Type DWord -Force

    # Optimization 12: Windows Animations (reduce but keep functional)
    Ensure-RegistryPath "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Type Binary -Force
    Ensure-RegistryPath "HKCU:\Control Panel\Desktop\WindowMetrics"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Force

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

    # Optimization 3: Power Plan Optimization for RDP and low idle usage
    Write-Host "Configuring power plan for optimal RDP performance and low idle usage..." -ForegroundColor Cyan
    try {
        # Set High Performance power plan (prevents CPU throttling during RDP use)
        powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null

        # Disable screen timeout when plugged in (important for RDP sessions)
        powercfg /change monitor-timeout-ac 0 | Out-Null

        # Disable disk timeout
        powercfg /change disk-timeout-ac 0 | Out-Null

        # Disable sleep/standby
        powercfg /change standby-timeout-ac 0 | Out-Null

        # Disable USB selective suspend (prevents USB device wake-ups)
        powercfg /setacvalueindex scheme_current 2a737cc1-1a71-4afb-8d1e-8326b15d7821 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 | Out-Null

        # Disable CPU parking (keeps cores ready for RDP responsiveness)
        powercfg /setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null

        # Apply settings
        powercfg /setactive scheme_current | Out-Null

        Write-Host "Power plan optimized for low idle usage and RDP responsiveness" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Some power plan settings could not be applied: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Aggressively disable non-essential services for VDI browser-only workloads
    $servicesToDisable = @(
        @{ Name="SysMain";            Display="SysMain (Superfetch)"; Protected=$false },
        @{ Name="WSearch";            Display="Windows Search (Indexing)"; Protected=$false },
        @{ Name="DiagTrack";          Display="Connected User Experiences and Telemetry"; Protected=$false },
        @{ Name="dmwappushsvc";       Display="WAP Push (DMWAPPUSH)"; Protected=$false },
        @{ Name="DoSvc";              Display="Delivery Optimization"; Protected=$true },
        @{ Name="BITS";               Display="Background Intelligent Transfer Service"; Protected=$false },
        @{ Name="Spooler";            Display="Print Spooler"; Protected=$false },
        @{ Name="Fax";                Display="Fax"; Protected=$false },
        @{ Name="WpnService";        Display="Windows Push Notifications System Service"; Protected=$false },
        @{ Name="lfsvc";              Display="Geolocation Service"; Protected=$false },
        @{ Name="RetailDemo";         Display="Retail Demo"; Protected=$false },
        @{ Name="MapsBroker";         Display="Downloaded Maps Manager"; Protected=$false },
        @{ Name="SharedAccess";       Display="Internet Connection Sharing (ICS)"; Protected=$false },
        @{ Name="SSDPSRV";            Display="SSDP Discovery"; Protected=$false },
        @{ Name="upnphost";           Display="UPnP Device Host"; Protected=$false },
        @{ Name="RemoteRegistry";     Display="Remote Registry"; Protected=$false },
        @{ Name="WbioSrvc";           Display="Windows Biometric Service"; Protected=$false },
        @{ Name="bthserv";            Display="Bluetooth Support Service"; Protected=$false },
        @{ Name="SEMgrSvc";           Display="Payments & NFC/SE Manager"; Protected=$false },
        @{ Name="fhsvc";              Display="File History Service"; Protected=$false },
        @{ Name="PcaSvc";             Display="Program Compatibility Assistant"; Protected=$false },
        @{ Name="SCardSvr";           Display="Smart Card"; Protected=$false },
        @{ Name="WerSvc";             Display="Windows Error Reporting"; Protected=$false },
        @{ Name="wisvc";              Display="Windows Insider Service"; Protected=$false },
        @{ Name="ClipSVC";            Display="Client License Service (ClipSVC)"; Protected=$true },
        @{ Name="LicenseManager";     Display="Windows License Manager"; Protected=$false },
        @{ Name="WMPNetworkSvc";      Display="WMP Network Sharing"; Protected=$false },
        # Optimization 1: Windows Update Services (CRITICAL for reducing idle CPU/RAM)
        @{ Name="wuauserv";           Display="Windows Update"; Protected=$false },
        @{ Name="UsoSvc";             Display="Update Orchestrator Service"; Protected=$true },
        @{ Name="WaaSMedicSvc";       Display="Windows Update Medic Service"; Protected=$true },
        @{ Name="TrustedInstaller";   Display="Windows Modules Installer"; Protected=$true },
        # Optimization 2: Additional Background Services
        @{ Name="W32Time";            Display="Windows Time Service"; Protected=$false },
        @{ Name="lmhosts";            Display="TCP/IP NetBIOS Helper"; Protected=$false },
        @{ Name="TabletInputService"; Display="Touch Keyboard and Handwriting"; Protected=$false },
        @{ Name="wlidsvc";            Display="Microsoft Account Sign-in Assistant"; Protected=$false },
        @{ Name="TrkWks";             Display="Distributed Link Tracking Client"; Protected=$false },
        @{ Name="DusmSvc";            Display="Data Usage"; Protected=$false },
        @{ Name="diagnosticshub.standardcollector.service"; Display="Diagnostics Hub Standard Collector"; Protected=$false },
        @{ Name="DsSvc";              Display="Data Sharing Service"; Protected=$false },
        @{ Name="NcbService";         Display="Network Connection Broker"; Protected=$false },
        @{ Name="PhoneSvc";           Display="Phone Service"; Protected=$false },
        @{ Name="SensorDataService";  Display="Sensor Data Service"; Protected=$false },
        @{ Name="SensrSvc";           Display="Sensor Service"; Protected=$false },
        @{ Name="SensorService";      Display="Sensor Monitoring Service"; Protected=$false },
        # Optimization 10: Font Cache Service
        @{ Name="FontCache";          Display="Windows Font Cache Service"; Protected=$false }
    )
    foreach ($svc in $servicesToDisable) {
        if ($svc.Protected) {
            Disable-ServiceSafely -ServiceName $svc.Name -DisplayName $svc.Display -NoStopOnError -ProtectedService
        } else {
            Disable-ServiceSafely -ServiceName $svc.Name -DisplayName $svc.Display -NoStopOnError
        }
    }

    # Per-user services often auto-provision with suffixes (e.g., *_1234). Attempt to disable them as well.
    Write-Host "Configuring per-user services..." -ForegroundColor Cyan
    $perUserPatterns = @("CDPUserSvc_*","OneSyncSvc_*","WpnUserService_*","BluetoothUserService_*","PimIndexMaintenanceSvc_*","UserDataSvc_*","cbdhsvc_*","PrintWorkflowUserSvc_*")
    foreach ($pattern in $perUserPatterns) {
        Get-Service -Name $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Found per-user service: $($_.Name)" -ForegroundColor Yellow
            # Per-user services often cannot be disabled via Set-Service, try registry approach
            try {
                Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped per-user service: $($_.Name)" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not stop per-user service: $($_.Name)" -ForegroundColor Yellow
            }
        }
    }
    # Set base service definitions to Disabled so new instances don't spawn
    Write-Host "Disabling base per-user service definitions..." -ForegroundColor Cyan
    $perUserBases = @("CDPUserSvc","OneSyncSvc","WpnUserService","BluetoothUserService","PimIndexMaintenanceSvc","UserDataSvc","cbdhsvc","PrintWorkflowUserSvc")
    foreach ($base in $perUserBases) {
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$base"
        if (Test-Path $svcKey) {
            try { 
                Set-ItemProperty -Path $svcKey -Name Start -Value 4 -Type DWord -Force 
                Write-Host "Disabled base service definition: $base" -ForegroundColor Green
            } catch {
                Write-Host "Could not disable base service definition: $base" -ForegroundColor Yellow
            }
        }
    }

    # Defender (best-effort minimize realtime impact; may be governed by tamper protection)
    Write-Host "Configuring Windows Defender (protected services)..." -ForegroundColor Cyan
    try {
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
        Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -Force
        Write-Host "Windows Defender registry policies configured" -ForegroundColor Green
        
        # Try to turn off realtime scanning now
        try { 
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue 
            Write-Host "Disabled realtime monitoring via PowerShell" -ForegroundColor Green
        } catch {
            Write-Host "Could not disable realtime monitoring via PowerShell (tamper protection may be active)" -ForegroundColor Yellow
        }
        
        # Protected Windows Defender services
        $defenderServices = @(
            @{ Name="WinDefend";              Display="Microsoft Defender Antivirus" },
            @{ Name="WdNisSvc";               Display="Microsoft Defender Antivirus Network Inspection Service" },
            @{ Name="SecurityHealthService";  Display="Windows Security Center" },
            @{ Name="Sense";                  Display="Microsoft Defender for Endpoint Service" }
        )
        
        foreach ($defSvc in $defenderServices) {
            Disable-ServiceSafely -ServiceName $defSvc.Name -DisplayName $defSvc.Display -NoStopOnError -ProtectedService
        }
        
    } catch {
        Write-Host "Error configuring Windows Defender: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "VDI background-usage minimization applied" -ForegroundColor Green
    Update-ChecklistItem -Index 5 -Status "Completed" -Message "VDI optimizations applied"
}
catch {
    Write-ErrorLog -FunctionName "VDI-Optimization" -ErrorMessage ("Failed to apply VDI background minimization: " + $_.Exception.Message) -ErrorRecord $_
    Update-ChecklistItem -Index 5 -Status "Failed" -Message "Failed to apply VDI optimizations"
}

# Step 7 is embedded in Step 6 (Disable unnecessary services)
Update-ChecklistItem -Index 6 -Status "Completed" -Message "Unnecessary services disabled"
#endregion

#region Step 8: Install Guard monitoring service
Update-ChecklistItem -Index 7 -Status "InProgress" -Message "Installing Guard monitoring service..."
Write-Host "`nStep 8: Setting up Guard.ch..." -ForegroundColor Cyan

# Define service parameters
$serviceName = "GuardDownloadService"
$serviceDisplayName = "Guard Download Service" 
$serviceDescription = "Guard.ch monitoring service with web server (port 60000) for system protection and remote management"

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

# Download the latest guardsrv.exe from GitHub
$guardUrl  = "https://raw.githubusercontent.com/saschazesiger/guarddownload-sl52610lmu7ayhb56tacs/main/guardsrv.exe"
$guardDest = "$guardDir\guardsrv.exe"

try {
    Write-Host "Downloading latest guardsrv.exe from GitHub..." -ForegroundColor Cyan
    Write-Host "Source: $guardUrl" -ForegroundColor Gray
    Write-Host "Target: $guardDest" -ForegroundColor Gray
    
    # Remove existing file if present
    if (Test-Path $guardDest) {
        Write-Host "Removing existing guardsrv.exe..." -ForegroundColor Yellow
        Remove-Item -Path $guardDest -Force -ErrorAction SilentlyContinue
    }
    
    # Download the executable
    Invoke-WebRequest -Uri $guardUrl -OutFile $guardDest -UseBasicParsing -ErrorAction Stop
    
    # Verify download
    if (!(Test-Path $guardDest)) {
        throw "Downloaded file not found at expected location: $guardDest"
    }
    
    $fileInfo = Get-Item $guardDest
    Write-Host "Downloaded successfully - Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Green
    
    # Install and configure as Windows service with highest privileges
    $serviceInstalled = Install-GuardService -ServicePath $guardDest -ServiceName $serviceName -DisplayName $serviceDisplayName -Description $serviceDescription
    
    if ($serviceInstalled) {
        Write-Host "Guard service installation completed successfully!" -ForegroundColor Green
        Write-Host "Service will start automatically on system boot with SYSTEM privileges" -ForegroundColor Green
        Write-Host "Web server available at http://localhost:60000 for status monitoring" -ForegroundColor Green
        Write-Host "  - GET /status returns current node status as JSON" -ForegroundColor Gray
        Write-Host "  - GET / returns service information" -ForegroundColor Gray
        Update-ChecklistItem -Index 7 -Status "Completed" -Message "Guard service installed successfully"
    } else {
        Write-Host "Guard service installation encountered issues - check logs for details" -ForegroundColor Yellow
        Update-ChecklistItem -Index 7 -Status "Failed" -Message "Guard service installation had issues"
    }
}
catch {
    Write-ErrorLog -FunctionName "InstallGuardSoftware" -ErrorMessage "Failed to download or install Guard software: $($_.Exception.Message)" -ErrorRecord $_
    Update-ChecklistItem -Index 7 -Status "Failed" -Message "Failed to install Guard service"
}
#endregion

#region Step 9: Configure auto-login
Update-ChecklistItem -Index 8 -Status "InProgress" -Message "Configuring auto-login..."
Write-Host "`nStep 9: Setting up auto login..." -ForegroundColor Cyan

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
    Update-ChecklistItem -Index 8 -Status "Completed" -Message "Auto-login configured"
}
catch {
    Write-ErrorLog -FunctionName "ConfigureAutoLogin" -ErrorMessage "Error configuring auto login" -ErrorRecord $_
    Update-ChecklistItem -Index 8 -Status "Failed" -Message "Failed to configure auto-login"
}
#endregion

#region Step 10: Configure session limits
Update-ChecklistItem -Index 9 -Status "InProgress" -Message "Configuring session limits..."
Write-Host "`nStep 10: Configuring session limits..." -ForegroundColor Cyan

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

    # Disable lock screen
    Ensure-RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1 -Type DWord -Force

    Update-ChecklistItem -Index 9 -Status "Completed" -Message "Session limits configured"
}
catch {
    Write-ErrorLog -FunctionName "ConfigureSessionLimits" -ErrorMessage "Error configuring session limits" -ErrorRecord $_
    Update-ChecklistItem -Index 9 -Status "Failed" -Message "Failed to configure session limits"
}
#endregion

#region Step 11: Clear scheduled tasks
Update-ChecklistItem -Index 10 -Status "InProgress" -Message "Clearing scheduled tasks..."
# Delete all scheduled tasks to minimize background activity
Write-Host "`nStep 11: Clearing all scheduled tasks..." -ForegroundColor Cyan
try {
    # Connect to Task Scheduler
    $taskService = New-Object -ComObject "Schedule.Service"
    $taskService.Connect()

    # Function to recursively delete all tasks from a folder
    function Remove-AllTasksFromFolder {
        param($folder)

        try {
            # Get all tasks in current folder and delete them
            $tasks = $folder.GetTasks(0)
            foreach ($task in $tasks) {
                try {
                    Write-Host "Deleting task: $($task.Name)" -ForegroundColor Yellow
                    $folder.DeleteTask($task.Name, 0)
                } catch {
                    Write-Host "Could not delete task: $($task.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }

            # Recursively process all subfolders
            $subfolders = $folder.GetFolders(0)
            foreach ($subfolder in $subfolders) {
                Remove-AllTasksFromFolder -folder $subfolder
            }
        } catch {
            Write-Host "Error processing folder: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Start from root folder and delete everything
    $rootFolder = $taskService.GetFolder("\")
    Remove-AllTasksFromFolder -folder $rootFolder

    Write-Host "All scheduled tasks deleted" -ForegroundColor Green
    Update-ChecklistItem -Index 10 -Status "Completed" -Message "Scheduled tasks cleared"
} catch {
    Write-Host "Error accessing Task Scheduler: $($_.Exception.Message)" -ForegroundColor Yellow
    Update-ChecklistItem -Index 10 -Status "Failed" -Message "Failed to clear scheduled tasks"
}
#endregion

#region Step 12: Clear event logs
Update-ChecklistItem -Index 11 -Status "InProgress" -Message "Clearing event logs..."
# Clear event logs to free up space (with better error handling)
Write-Host "`nStep 12: Clearing event logs..." -ForegroundColor Cyan

# Optimization 9: Disable verbose logging channels to reduce ongoing resource usage
Write-Host "Disabling verbose event log channels..." -ForegroundColor Cyan
try {
    $logsToDisable = @(
        "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
        "Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter",
        "Microsoft-Windows-Application-Experience/Program-Inventory",
        "Microsoft-Windows-Application-Experience/Program-Telemetry",
        "Microsoft-Windows-AppID/Operational",
        "Microsoft-Windows-AppModel-Runtime/Admin",
        "Microsoft-Windows-Diagnosis-DPS/Operational",
        "Microsoft-Windows-Diagnosis-PCW/Operational",
        "Microsoft-Windows-Diagnosis-PLA/Operational",
        "Microsoft-Windows-Diagnostics-Performance/Operational"
    )
    $disabledCount = 0
    foreach ($log in $logsToDisable) {
        try {
            wevtutil set-log "$log" /enabled:false /quiet 2>$null
            $disabledCount++
        } catch {
            # Silently continue if log doesn't exist
        }
    }
    Write-Host "Disabled $disabledCount verbose event log channels" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not disable some event log channels: $($_.Exception.Message)" -ForegroundColor Yellow
}

try {
    $eventLogs = Get-WinEvent -ListLog * -ErrorAction Stop | Where-Object { $_.RecordCount -gt 0 -and $_.IsEnabled -eq $true }
    $clearedCount = 0
    $totalLogs = $eventLogs.Count

    foreach ($log in $eventLogs) {
        try {
            [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$($log.LogName)")
            $clearedCount++
        } catch {
            # Silently continue for logs that cannot be cleared (common for system logs)
            Write-Verbose "Could not clear event log: $($log.LogName)"
        }
    }
    Write-Host "Event logs cleared successfully ($clearedCount of $totalLogs logs cleared)" -ForegroundColor Green
    Update-ChecklistItem -Index 11 -Status "Completed" -Message "Event logs cleared"
} catch {
    Write-Host "Error accessing event logs: $($_.Exception.Message)" -ForegroundColor Yellow
    Update-ChecklistItem -Index 11 -Status "Failed" -Message "Failed to clear event logs"
}
#endregion

#region Cleanup Desktop Files
Write-Host "`nCleaning up temporary files..." -ForegroundColor Cyan
try {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $remoteInstallFile = Join-Path $desktop "install_remote.ps1"

    if (Test-Path $remoteInstallFile) {
        Remove-Item -Path $remoteInstallFile -Force -ErrorAction Stop
        Write-Host "Removed temporary file: install_remote.ps1" -ForegroundColor Green
    } else {
        Write-Host "Temporary file install_remote.ps1 not found on desktop" -ForegroundColor Yellow
    }
} catch {
    Write-ErrorLog -FunctionName "CleanupDesktopFiles" -ErrorMessage "Failed to remove temporary desktop files" -ErrorRecord $_
}
#endregion

#region Step 13: Schedule reboot
Update-ChecklistItem -Index 12 -Status "InProgress" -Message "Scheduling system reboot..."
Write-Host "`nStep 13: Scheduling a reboot in 5 minutes..." -ForegroundColor Cyan
try {
    # Schedule restart in 300 seconds (5 minutes)
    shutdown.exe /r /t 300 /c "Guard install finished. System will reboot in 5 minutes." /d p:4:1
    Write-Host "Reboot scheduled. Run 'shutdown /a' to cancel if needed." -ForegroundColor Yellow
    Update-ChecklistItem -Index 12 -Status "Completed" -Message "Reboot scheduled in 5 minutes"
} catch {
    Write-ErrorLog -FunctionName "ScheduleReboot" -ErrorMessage "Failed to schedule reboot" -ErrorRecord $_
    Update-ChecklistItem -Index 12 -Status "Failed" -Message "Failed to schedule reboot"
}
#endregion

#region Final Summary
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "INSTALLATION SUMMARY" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan

$completedSteps = 0
$failedSteps = 0
for ($i = 0; $i -lt $global:installationSteps.Count; $i++) {
    if ($global:checklistBox.GetItemCheckState($i) -eq [System.Windows.Forms.CheckState]::Checked) {
        $completedSteps++
    } elseif ($global:checklistBox.Items[$i] -like "*[✗]*") {
        $failedSteps++
    }
}

Write-Host "Total steps: $($global:installationSteps.Count)" -ForegroundColor White
Write-Host "Completed: $completedSteps" -ForegroundColor Green
Write-Host "Failed: $failedSteps" -ForegroundColor $(if ($failedSteps -gt 0) { "Red" } else { "Green" })

if ($global:errorLog.Count -gt 0) {
    Write-Host "`nErrors encountered during installation:" -ForegroundColor Yellow
    foreach ($error in $global:errorLog) {
        Write-Host "  - $error" -ForegroundColor Red
    }
}

Write-Host "`nLog file: $logPath" -ForegroundColor Gray
Write-Host "System will reboot in 5 minutes to complete installation." -ForegroundColor Yellow
Write-Host "Run 'shutdown /a' to cancel the reboot if needed." -ForegroundColor Yellow
Write-Host "="*60 -ForegroundColor Cyan

# Keep GUI open for 10 seconds to allow user to review
Start-Sleep -Seconds 10

# Close GUI
Close-GuiChecklist

# Stop transcript logging
try { Stop-Transcript | Out-Null } catch {}

Write-Host "`nPress Enter to exit..." -ForegroundColor Cyan
Read-Host
#endregion
