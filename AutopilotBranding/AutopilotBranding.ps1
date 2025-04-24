
function Log() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$false)] [String] $message
	)

	$ts = get-date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$ts $message"
}

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# Create output folder
if (-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding"))
{
    Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding" -Force
	Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

}

# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

# Creating tag file
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

# PREP: Load the Config.xml
$installFolder = "$PSScriptRoot\"
Log "Install folder: $installFolder"
Log "Loading configuration: $($installFolder)Config.xml"
[Xml]$config = Get-Content "$($installFolder)Config.xml"

# STEP 1: Apply a custom start menu and taskbar layout
$ci = Get-ComputerInfo
if ($ci.OsBuildNumber -le 22000) {
	Log "Importing layout: $($installFolder)Layout.xml"
	Copy-Item "$($installFolder)Layout.xml" "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
} else {
	Log "Importing Start menu layout: $($installFolder)Start2.bin"
	MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$($installFolder)Start2.bin" "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
	Log "Importing Taskbar layout: $($installFolder)TaskbarLayoutModification.xml"
	MkDir -Path "C:\Windows\OEM\" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$($installFolder)TaskbarLayoutModification.xml" "C:\Windows\OEM\TaskbarLayoutModification.xml" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v LayoutXMLPath /t REG_EXPAND_SZ /d "%SystemRoot%\OEM\TaskbarLayoutModification.xml" /f | Out-Host
	Log "Unpin the Microsoft Store app from the taskbar"
	reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host
	reg.exe add "HKLM\TempUser\Software\Policies\Microsoft\Windows\Explorer" /v NoPinningStoreToTaskbar /t REG_DWORD /d 1 /f | Out-Host
	reg.exe unload HKLM\TempUser | Out-Host
}

# STEP 2: Configure background
reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host

Log "Setting up Autopilot theme"
Mkdir "C:\Windows\Resources\OEM Themes" -Force | Out-Null
Copy-Item "$installFolder\Autopilot.theme" "C:\Windows\Resources\OEM Themes\Autopilot.theme" -Force
Mkdir "C:\Windows\web\wallpaper\Autopilot" -Force | Out-Null
Copy-Item "$installFolder\Autopilot.jpg" "C:\Windows\web\wallpaper\Autopilot\Autopilot.jpg" -Force
Log "Setting Autopilot theme as the new user default"
reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host

# STEP 2A: Stop Start menu from opening on first logon
reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StartShownOnUpgrade /t REG_DWORD /d 1 /f | Out-Host

# STEP 2B: Hide "Learn more about this picture" from the desktop
reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f | Out-Host

# STEP 2C: Disable Windows Spotlight as per https://github.com/mtniehaus/AutopilotBranding/issues/13#issuecomment-2449224828
Log "Disabling Windows Spotlight for Desktop"
reg.exe add "HKLM\TempUser\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSpotlightCollectionOnDesktop /t REG_DWORD /d 1 /f | Out-Host

# STEP 2D: Disable Windows Spotlight on LockScreen
reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'RotatingLockScreenOverlayEnabled' /t REG_DWORD /d 0 /f | Out-Null

reg.exe unload HKLM\TempUser | Out-Host

#STEP 2E: #Disable the Animations when loggin new " Please wait, We're almost done..."
#Can be set as Intune Policy aswell this makes sure its set at first login after Autopilot completes
Log "Diable First Time Logon Animations"
#$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
#New-ItemProperty -Path $regPath -Name EnableFirstLogonAnimation -Value 0 -type DWord
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f



# STEP 3: Set time zone (if specified)
if ($config.Config.TimeZone) {
	Log "Setting time zone: $($config.Config.TimeZone)"
	Set-Timezone -Id $config.Config.TimeZone
}
else {
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}

# STEP 4: Remove specified provisioned apps if they exist
Log "Removing specified in-box provisioned apps"
$apps = Get-AppxProvisionedPackage -online
$config.Config.RemoveApps.App | % {
	$current = $_
	$apps | ? {$_.DisplayName -eq $current} | % {
		try {
			Log "Removing provisioned app: $current"
			$_ | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
		} catch { }
	}
}

# STEP 5: Install OneDrive per machine
if ($config.Config.OneDriveSetup) {
	Log "Downloading OneDriveSetup"
	$dest = "$($env:TEMP)\OneDriveSetup.exe"
	$client = new-object System.Net.WebClient
	$client.DownloadFile($config.Config.OneDriveSetup, $dest)
	Log "Installing: $dest"
	$proc = Start-Process $dest -ArgumentList "/allusers /silent" -WindowStyle Hidden -PassThru
	$proc.WaitForExit()
	Log "OneDriveSetup exit code: $($proc.ExitCode)"
}

#STEP 5A: Exclude Shortcuts from Syncing in OneDrive.
reg.exe add "HKLM\Software\Policies\Microsoft\OneDrive" /v ExcludedFileExtensions /t REG_SZ /d ".lnk" /f

# STEP 6: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
Log "Turning off (old) Edge desktop shortcut"
if (Test-Path "C:\Users\Public\Desktop\Microsoft Edge.lnk") { Remove-Item "C:\Users\Public\Desktop\Microsoft Edge.lnk" -Force }
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host

# STEP 7: Add language packs
Get-ChildItem "$($installFolder)LPs" -Filter *.cab | % {
	Log "Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}

# STEP 8: Change language
if ($config.Config.Language) {
	Log "Configuring language using: $($config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($installFolder)$($config.Config.Language)`""
}

# STEP 9: Add features on demand, Disable Optional Features, Remove Windows Capabilities
$currentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
if ($currentWU -eq 1)
{
	Log "Turning off WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
	Restart-Service wuauserv
}
# Step 9A: Add features on demand
if ($config.Config.AddFeatures.Feature.Count -gt 0)
{
	$config.Config.AddFeatures.Feature | % {
		Log "Adding Windows feature: $_"
		Add-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue | Out-Null
	}
}
# Step 9B: Disable Optional features
if ($config.Config.DisableOptionalFeatures.Feature.Count -gt 0)
{
	$EnabledOptionalFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}
	foreach ($EnabledFeature in $EnabledOptionalFeatures) {
		if ($config.Config.DisableOptionalFeatures.Feature -contains $EnabledFeature.FeatureName) {
			Log "Disabling Optional Feature:  $($EnabledFeature.FeatureName)"
			Disable-WindowsOptionalFeature -Online -FeatureName $EnabledFeature.FeatureName -NoRestart | Out-Null
		}
	}
}
# Step 9C: Remove Windows Capabilities
if ($config.Config.RemoveCapability.Capability.Count -gt 0)
{
	$InstalledCapabilities = Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"}
	foreach ($InstalledCapability in $InstalledCapabilities) {
		if ($config.Config.RemoveCapability.Capability -contains $InstalledCapability.Name.Split("~")[0]) {
			Log "Removing Windows Capability:  $($InstalledCapability.Name)"
			Remove-WindowsCapability -Online -Name $InstalledCapability.Name  | Out-Null
		}
	}
}

if ($currentWU -eq 1)
{
	Log "Turning on WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
	Restart-Service wuauserv
}

<#i
# STEP 10: Customize default apps
if ($config.Config.DefaultApps) {
	Log "Setting default apps: $($config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$($installFolder)$($config.Config.DefaultApps)`"
}

# STEP 11: Set registered user and organization
Log "Configuring registered user information"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host

# STEP 12: Configure OEM branding info
f ($config.Config.OEMInfo)
{
	Log "Configuring OEM branding info"

	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$installFolder\$($config.Config.OEMInfo.Logo)" "C:\Windows\$($config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}


# STEP 13: Enable UE-V
Log "Enabling UE-V"
Enable-UEV
Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
Get-ChildItem "$($installFolder)UEV" -Filter *.xml | % {
	Log "Registering template: $($_.FullName)"
	Register-UevTemplate -Path $_.FullName
}

#>

# STEP 14: Disable network location fly-out
Log "Turning off network location fly-out"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f
 
reg load HKU\Default C:\Users\Default\NTUSER.DAT

# STEP 16: Remove Searchbar for all users new Way as of Win 11 23h2 thanks to SweJorgen and Woody over on GetRUbix Discord for pointing me to this. Create a run once to set the SearchTaskbarMode, recommend 0 or 1
Log "Setting Searchbox to Icon Only"
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v 'RemoveSearch' /t REG_SZ /d "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /t REG_DWORD /v SearchboxTaskbarMode /d 1 /f" /f

# STEP 17: Disable Taskview and Chat Button
Log "Disabling Chat and Taskview Icons"
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f | Out-Null

# STEP 17A : Remove Widget
#Remove Widgets New Work around October 2024, Tested with Win 11 24H2
Log "Hidding Widgets on Taskbar"
copy-item (Get-Command reg).Source .\reg1.exe
#.\reg1.exe load HKU\Default C:\Users\Default\NTUSER.DAT
.\reg1.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f | Out-Null
#.\reg1.exe unload HKU\Default
sleep 5
remove-item .\reg1.exe

# STEP 18: Setup Left StartMenu Alignment
Log "Set Left Start Menu Alignment"
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null

#STEP 18A: Right Click Context Menu restore
reg.exe add "HKU\Default\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve | Out-Null

#STEP 18B: Show "Run as different User" in context menu
Log "Enable Run as otherUSer"
reg.exe add "HKU\Default\Software\Policies\Microsoft\Windows\Explorer" /f | Out-Null
reg.exe add "HKU\Default\Software\Policies\Microsoft\Windows\Explorer" /v ShowRunAsDifferentUserInStart /t REG_DWORD /d 1 /f | Out-Null

#STEP 19: Stop Bing Search in results of TaskBar

Log "Bing Search Disabled in Taskbar"
reg.exe add "HKU\Default\Software\Policies\Microsoft\Windows\Explorer" /v BingSearchEnabled /t REG_DWORD /d 0 /f | Out-Null

#STEP 20: REmove adds and suggestions in Windows where possible.
Log " Disable Tips Recommendations for new Apps"
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f
#STEP 20A:Disable SPonsered Apps like Spotify or the Candy Crushes from coming back or silently installing
Log "Disabling Sponsored Apps"
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContentEnabled' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'PreInstalledAppsEnabled' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SilentInstalledAppsEnabled' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'ContentDeliveryAllowed' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'OemPreInstalledAppsEnabled' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'PreInstalledAppsEverEnabled' /t REG_DWORD /d 0 /f  | Out-Null

#STEP 20E: Disable Windows Tips 
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SoftLandingEnabled' /t REG_DWORD /d 0 /f | Out-Null

#STEP 20B: Like what you see?" tips and suggestions appear on the Windows Spotlight lock screen Disable
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-338387Enabled' /t REG_DWORD /d 0 /f  | Out-Null

#STEP 20G:  Disable Windows Welcome Experience
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-310093Enabled' /t REG_DWORD /d 0 /f  | Out-Null

#STEP 20H: Disable ADs for apps in Start Menu
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-338388Enabled' /t REG_DWORD /d 0 /f  | Out-Null

#STEP 20C: To Turn Off "Get tips, tricks, and suggestions as you use Windows"
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-338389Enabled' /t REG_DWORD /d 0 /f  | Out-Null

#STEP 20D: Turn Off Suggested Content in Settings
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-338393Enabled' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-353694Enabled' /t REG_DWORD /d 0 /f  | Out-Null
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SubscribedContent-353696Enabled' /t REG_DWORD /d 0 /f  | Out-Null

#STEP 20F: Turn Off App suggestions in Taksbar 
reg.exe add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v 'SystemPaneSuggestionsEnabled' /t REG_DWORD /d 0 /f  | Out-Null

#Unload the DEFUALT\User Hive
reg unload HKU\Default

# STEP 22: Disable Powersehll v2
Log "Disabling PowerShell v2.0"
try {
    $PoShv2Enabled = Get-WindowsOptionalFeature -FeatureName "MicrosoftWindowsPowerShellV2Root" -Online | Select-Object -ExpandProperty State
} catch {
    Write-Error "Failed to get the state of the PowerShell v2.0 feature: : $($_.Exception.Message)"
}
if ($PoShv2Enabled -eq "Enabled") {
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Continue -NoRestart
    } catch {
        Write-Error "Failed to disable the PowerShell v2.0 feature: $($_.Exception.Message)"
    }
}

# STEP 23: Remove the registry keys for Dev Home and Outlook New
# This is a workaround for the issue where the Dev Home and Outlook New apps are installed by default from https://github.com/mtniehaus/AutopilotBranding/pull/20
Log "Disabling Windows 11 Dev Home and Outlook New"
$DevHome = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate"
$OutlookNew = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate"
if (Test-Path -Path $DevHome) {
    Log "Found --> Removing DevHome"
    Remove-Item -Path $DevHome -Force
}
if (Test-Path -Path $OutlookNew) {
    Log "Found --> Removing Outlook NEW"
    Remove-Item -Path $OutlookNew -Force
}

#STEP 24 Remove Pre-installed Office/ MS 365 
#Some Vendors like Dell may deploy 3 language versions -EN -FR -ES. Try and remove all C2R versions of office products in one go.
Log "Creating XML uninstaller"
$xml = @"
<Configuration>
  <Display Level="None" AcceptEULA="True" />
  <Property Name="FORCEAPPSHUTDOWN" Value="True" />
  <Remove All="TRUE">
  </Remove>
</Configuration>
"@

##write XML to the debloat folder
$xml | Out-File -FilePath "C:\ProgramData\Microsoft\AutopilotBranding\o365.xml"

Log "Downloading ODT"
##Download the ODT from Git. If you are forking you can publish your own or addjust code below to download the latest.
$ProgressPreference = 'SilentlyContinue'
$odturl = "https://github.com/HedgeComp/WindowsOtto-PilotBranding/raw/main/ODT/odt.exe"
$odtdestination = "C:\ProgramData\Microsoft\AutopilotBranding\odt.exe"
Invoke-WebRequest -Uri $odturl -OutFile $odtdestination -Method Get -UseBasicParsing
$ProgressPreference = 'Continue'

##Run it
Log "Running ODT"
Start-Process -FilePath "C:\ProgramData\Microsoft\AutopilotBranding\odt.exe" -ArgumentList "/configure C:\ProgramData\Microsoft\AutopilotBranding\o365.xml" -WindowStyle Hidden -Wait

Stop-Transcript
