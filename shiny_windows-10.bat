@echo off
title Shiny Windows 10

:: Also means 'winget' and other .appx reliant software break
set /A break_windows_store=0

:: Can be reverted with 'sfc /scannow'; used to entirely disable Windows Defender
set /A delete_windows_security=1

:: Will break SteamVR Base Station support
set /A disable_bluetooth_audio_support=0

:: Disables GPS services, which always run even if there's no GPS hardware installed
set /A disable_geolocation=1

:: Routing through IPv6 is worse than IPv4 in some areas (higher latency/ping)
set /A disable_ipv6=0

:: Instructions on how to stay secure are located @ README.adoc
set /A disable_mitigations=1

:: Printers are heavily exploitable, avoid using one if possible
set /A disable_printer_support=1

:: https://nvidia.custhelp.com/app/answers/detail/a_id/5157
:: https://nvidia.custhelp.com/app/answers/detail/a_id/5159/~/v-sync-off-not-recommended-as-a-global-setting-starting-with-driver-version
set /A enable_mpo=1

:: Install .NET Framework 2 and 3.5 for backwards compatibility
set /A install_dotnet_2_and_3=0

:: If Jumbo Packets being disabled concerns you, look into what else is changed before using it.
set /A network_adapter_tweaks=1

:: Makes disks using the default file system (NTFS) faster, but disables File History and File Access Dates
set /A ntfs_tweaks=1

:: Disables Game DVR, Game Bar, and all Xbox functionality; heavily reliant on each other
set /A remove_xbox=0

:: Disables mouse smoothing across all software & games
set /A run_markc_mousefix=1

:: TODO DESCRIPTION
set /A disable_netbios=1

:: Disable Windows Script Host (.vbs/.vbe/.ws/.wsh/.js/.jse); decreases attack surface, and without downsides (for some)
set /A z-disable_script_host=0

reg.exe query HKU\S-1-5-19 || (
	echo ==== Error ====
	echo Right click on this file and select 'Run as administrator'
	echo Press any key to exit...
	Pause>nul
	exit /b
)

:: If there was a scheduled reboot, deny it from now and in the future.
takeown /R /F /D y C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator
del /F /S /Q C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\*
copy /y NUL %windir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot
copy /y NUL %windir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot_AC
copy /y NUL %windir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery
icacls.exe "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator" /inheritance:r /deny "Everyone:(OI)(CI)(F)" "ANONYMOUS LOGON:(OI)(CI)(F)"

:: If these are disabled, Windows Update will break and so will this script
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /v "Start" /t REG_DWORD /d 3 /f
:: Specifically breaks Windows Store if disabled previously (by you)
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /v "Start" /t REG_DWORD /d 3 /f

sc.exe start AppXSvc
sc.exe start ClipSVC
sc.exe start MpsSvc
sc.exe start StorSvc

cls
echo ==== Instructions ====
echo.
echo Temporarily disable all anti-virus/anti-malware software before proceeding
echo.
echo ==== Current settings ====
echo.
echo break_windows_store = %break_windows_store%
echo delete_windows_security = %delete_windows_security%
echo disable_bluetooth_audio_support = %disable_bluetooth_audio_support%
echo disable_geolocation = %disable_geolocation%
echo disable_ipv6 = %disable_ipv6%
echo disable_mitigations = %disable_mitigations%
echo disable_printer_support = %disable_printer_support%
echo enable_mpo = %enable_mpo%
echo install_dotnet_2_and_3 = %install_dotnet_2_and_3%
echo network_adapter_tweaks = %network_adapter_tweaks%
echo ntfs_tweaks = %ntfs_tweaks%
echo remove_xbox = %remove_xbox%
echo run_markc_mousefix = %run_markc_mousefix%
echo.
Pause
cd %SystemRoot%\System32

:: Won't make a restore point if there's already one within the past 24 hours
WMIC.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Before applying the Shiny Windows script", 100, 7

:: Allow PowerShell scripts in current directory
powershell.exe -Command "Get-ChildItem *.ps*1 -recurse | Unblock-File"

:: Activation is required for some changes; requires ClipSVC to fully work
start /high /b "" "%~dp0\MAS_1.4\KMS38_Activation.cmd"

:: Prefer to disable "Full Screen Optimizations"; FSO uses more GPU, lowering FPS in GPU-intensive games
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f

:: >> [GROUP 1] File Manager & Windows Shell tweaks <<

reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "NoAutomaticFolderType" /t REG_SZ /f /d "reg.exe add \"HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\Shell\Bags\AllFolders\Shell\" /v FolderType /t REG_SZ /d NotSpecified /f"
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
:: Disable Explorer's thumbnail border shadows
reg.exe add "HKCR\SystemFileAssociations\image" /v "Treatment" /t REG_DWORD /d 0 /f
reg.exe add "HKCR\SystemFileAssociations\image" /v "TypeOverlay" /t REG_SZ /d "" /f

:: Don't waste CPU cycles to remove thumbnail caches
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v "Autorun" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v "Autorun" /t REG_DWORD /d 0 /f

:: Performance Options -> Visual Effects -> Custom
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9012038010000000 /f

:: Show window contents while dragging
reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d 1 /f
:: Smooth edges of screen fonts
reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
:: Show translucent selection rectangle
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 1 /f
:: Show thumbnails instead of icons	
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f
:: Use drop shadows for icon labels on the desktop
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 1 /f

:: Don't check for an active connection through Microsoft's servers
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /t REG_DWORD /d 0 /f
:: Set the "blue" Solid colour Background; using a wallpaper keeps an image loaded into memory
reg.exe add "HKCU\Control Panel\Desktop" /v "TileWallpaper" /t REG_SZ /d 0 /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WallPaper" /t REG_SZ /d "" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperOriginX" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperOriginY" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperStyle" /t REG_SZ /d 10 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Colors" /v "Background" /t REG_SZ /d "58 110 165" /f

:: Disable JPEG wallpaper quality reduction
reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f

:: >> [GROUP 1 END] <<


:: >> [GROUP 2] Privacy enhancers (ask Microsoft nicely to turn off data collectors, which waste system resources) <<

reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f
:: Disable Error Reporting
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
:: Disable Sharing of handwriting data
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
:: Remove Search/Cortana from taskbar
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
:: Remove People buttom from taskbar
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
:: Disable Advertising ID
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Id" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Id" /f

:: Disable transmission of typing information
reg.exe add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
:: Disable Microsoft conducting experiments with this machine
reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d 0 /f
:: Disable "Customer Experience Improvement Program"
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f

:: Disable syncing of text messages to Microsoft
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d 0 /f
:: Disable application access to user account information
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
:: Disable tracking of application startups
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f
:: Disable application access of diagnostic information
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f
:: Disable user steps recorder
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:: Disable synchronization of all settings to Microsoft
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
:: Disable Input Personalization
reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

:: No web search through Start Menu
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

:: >> [GROUP 2 END] <<


:: >> [GROUP 3] Disable legacy features to increase security <<

:: Disable SMBv1, it's insecure and slow compared to SMBv3
powershell.exe -Command "Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName "SMB1Protocol""
powershell.exe -Command "Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName "SMB1Protocol-Client""
powershell.exe -Command "Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName "SMB1Protocol-Server""
powershell.exe -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled

:: Disable legacy PowerShell
powershell.exe -Command "Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName "MicrosoftWindowsPowerShellV2Root""
powershell.exe -Command "Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName "MicrosoftWindowsPowerShellV2""

if %disable_netbios%==0 (
	powershell.exe -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip*' -Name NetbiosOptions -Value 0"
)
if %disable_netbios%==1 (
	powershell.exe -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip*' -Name NetbiosOptions -Value 2"
)

:: >> [GROUP 3 END] <<


:: Disable updates for Speech Recognition and Speech Synthesis
reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d 0 /f

:: Disable peer-to-peer functionality in Windows Update
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f

:: Disable feedback reminders
reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoOnlineAssist" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

:: Disable Sticky Keys, Toggle Keys, and Filter Keys
reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 50 /f
reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d 58 /f
reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d 122 /f

:: Never use non-stock configurations with Insider builds (specially Fast Ring)
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f

if %break_windows_store%==1 (
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d 4 /f
)
if %delete_windows_security%==1 (
	bcdedit.exe /set tpmbootentropy ForceDisable
	bcdedit.exe /set hypervisorlaunchtype off
	takeown.exe /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
	icacls.exe "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
	taskkill.exe /im smartscreen.exe /f
	del "%WinDir%\System32\smartscreen.exe" /s /f /q
	takeown.exe /s %computername% /u %username% /f "%WinDir%\System32\SecurityHealthSystray.exe"
	icacls.exe "%WinDir%\System32\SecurityHealthSystray.exe" /grant:r %username%:F
	taskkill.exe /im SecurityHealthSystray.exe /f
	del "%WinDir%\System32\SecurityHealthSystray.exe" /s /f /q
	takeown.exe /s %computername% /u %username% /f "%WinDir%\System32\SecurityHealthHost.exe"
	icacls.exe "%WinDir%\System32\SecurityHealthHost.exe" /grant:r %username%:F
	taskkill.exe /im SecurityHealthHost.exe /f
	del "%WinDir%\System32\SecurityHealthHost.exe" /s /f /q

	takeown /s %computername% /u %username% /f "C:\Program Files\Windows Defender" /R
	icacls.exe "C:\Program Files\Windows Defender\*" /grant:r %username%:F
	rmdir /S /Q "C:\Program Files\Windows Defender"

	takeown /s %computername% /u %username% /f "C:\Program Files\Windows Defender Advanced Threat Protection" /R
	icacls.exe "C:\Program Files\Windows Defender Advanced Threat Protection" /grant:r %username%:F
	rmdir /S /Q "C:\Program Files\Windows Defender Advanced Threat Protection"

	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t "REG_DWORD" /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t "REG_DWORD" /d 0 /f
	schtasks.exe /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
	:: reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
)
:: Tuned specifically for lowest latency variance (gaming)
if %network_adapter_tweaks%==1 (
	powershell.exe -Command ".\network_adapter_tweaks.ps1"
	:: Don't allow the Multimedia Class Scheduler Service to throttle
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f

	reg.exe add "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d 20 /f
	netsh.exe int tcp set global dca=enabled
	netsh.exe int tcp set global netdma=enabled
	netsh.exe int tcp set global rss=disabled
	netsh.exe int tcp set global rsc=disabled
	netsh.exe int tcp set global timestamps=disabled
)
if %install_dotnet_2_and_3%==1 (
	dism.exe /Online /Enable-Feature /NoRestart /featurename:NetFX3
)

if %enable_mpo%==1 (
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /f
)
if %disable_mitigations%==1 (
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f 
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
	:: Use the faster but less secure Hyper-V scheduler
	bcdedit.exe /set hypervisorschedulertype classic
	:: Allow Intel TSX
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v DisableTsx /t REG_DWORD /d 0 /f
	powershell.exe -Command "Set-ProcessMitigation -PolicyFilePath disable_system_exploit_mitigations.xml"
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v "Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
)
if %disable_ipv6%==1 (
	sc.exe stop iphlpsvc
	sc.exe stop IpxlatCfgSvc
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc" /v Start /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v Start /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "disable_ipv6" /t REG_SZ /f /d "powershell -Command Set-NetAdapterBinding -Name '*' -DisplayName 'Internet Protocol Version 6 (TCP/IPv6)' -Enabled 0"
)

:: Disable UAC: EnableLUA at 0 will break startup of some software, such as https://eddie.website/
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f

:: Never expire Windows' login password
net accounts /maxpwage:unlimited
:: Unhide lots of Power Plan options
powershell.exe -Command ".\enable-all-advanced-power-settings.ps1 | Out-File powercfg.ps1 | .\powercfg.ps1"

:: Bitsum Highest Performance profile cannot install if any Power Plans were previously removed
powercfg –restoredefaultschemes
:: Sleep mode achieves the same goal while not hammering the primary hard drive, but will break in power outages/surges; regardless, leaving a PC unattended is bad
powercfg.exe /hibernate off
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V HiberbootEnabled /T REG_DWORD /D 0 /F

:: Increasing overall system latency/DPC for the sake of minimal power saving is bad
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
:: Automated file cleanup (without user interaction) is a bad idea
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d 0 /f
reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense" /f

schtasks.exe /Change /DISABLE /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn"

schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\AppID\SmartScreenSpecific"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Autochk\Proxy"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\CertificateServicesClient\UserTask-Roam"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Chkdsk\ProactiveScan"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Clip\License Validation"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Diagnosis\Scheduled"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\DiskFootprint\Diagnostics"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\DiskFootprint\StorageSense"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Feedback\Siuf\DmClient"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\HelloFace\FODCleanupTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\InstallService\ScanForUpdates"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\InstallService\SmartRetry"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Location\Notifications"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Location\WindowsActionDialog"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Maintenance\WinSAT"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Maps\MapsToastTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Maps\MapsUpdateTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\MUI\LPRemove"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Multimedia\SystemSoundsService"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Plug and Play\Device Install Reboot Required"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Printing\EduPrintProv"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Ras\MobilityManager"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Registry\RegIdleBackup"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Setup\SetupCleanupTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Speech\HeadsetButtonPress"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\USB\Usb-Notifications"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\WDI\ResolutionHost"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\WindowsUpdate\sih"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\WOF\WIM-Hash-Management"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\WOF\WIM-Hash-Validation"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"
schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\WS\WSTask"

reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "removetask1" /t REG_SZ /f /d "schtasks.exe /Delete /F /TN \Microsoft\Windows\RetailDemo\CleanupOfflineContent"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "removetask2" /t REG_SZ /f /d "schtasks.exe /Delete /F /TN \Microsoft\Windows\Setup\SetupCleanupTask"

attrib +R C:\Windows\System32\SleepStudy\UserNotPresentSession.etl

schtasks.exe /Create /TR "cmd /c shutdown /r /t 10 /f & schtasks.exe /Delete /F /TN Reboot" /RU Administrator /TN Reboot /SC ONLOGON /IT /V1 /Z

if exist "C:\Windows\Microsoft.NET\Framework\v2.0.50727\ngen.exe" (
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "DOTNET20_Optimize1" /t REG_SZ /f /d "schtasks.exe /Create /Delay 0000:02 /TR \"cmd /c start /min C:\Windows\Microsoft.NET\Framework\v2.0.50727\ngen.exe ExecuteQueuedItems\" /RU Administrator /TN NETOptimize1 /SC ONLOGON /IT"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "DOTNET20_Optimize2" /t REG_SZ /f /d "schtasks.exe /Create /Delay 0000:02 /TR \"cmd /c start /min C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ngen.exe ExecuteQueuedItems\" /RU Administrator /TN DOTNET20_Optimize3 /SC ONLOGON /IT"
)

if exist "C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe" (
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "DOTNET40_Optimize1" /t REG_SZ /f /d "schtasks.exe /Create /Delay 0000:02 /TR \"cmd /c start /min C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe ExecuteQueuedItems\" /RU Administrator /TN NETOptimize2 /SC ONLOGON /IT"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "DOTNET40_Optimize2" /t REG_SZ /f /d "schtasks.exe /Create /Delay 0000:02 /TR \"cmd /c start /min C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe ExecuteQueuedItems\" /RU Administrator /TN DOTNET40_Optimize3 /SC ONLOGON /IT"
	schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical"
	schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
	schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"
	schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319"
)

reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "AutoLogger1" /t REG_SZ /f /d "reg.exe add \"HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession\" /v Start /t REG_DWORD /d 0 /f"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "AutoLogger2" /t REG_SZ /f /d "reg.exe add \"HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro\" /v Start /t REG_DWORD /d 0 /f"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "AutoLogger3" /t REG_SZ /f /d "reg.exe add \"HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession\" /v Start /t REG_DWORD /d 0 /f"

reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v Start /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v Start /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vdrvroot" /v Start /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\volmgrx" /v Start /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wof" /v Start /t REG_DWORD /d 3 /f

bcdedit.exe /deletevalue useplatformclock
bcdedit.exe /set disabledynamictick yes
bcdedit.exe /set uselegacyapicmode no
bcdedit.exe /set x2apicpolicy enable
bcdedit.exe /set bootux disabled
bcdedit.exe /set bootmenupolicy legacy
bcdedit.exe /set bootlog yes
bcdedit.exe /set custom:16000067 true

:: NTFS tweaks
if %ntfs_tweaks%==1 (
	fsutil behavior set disablelastaccess 3
	fsutil behavior set encryptpagingfile 0
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IoBlockLegacyFsFilters" /t REG_DWORD /d 1 /f
	schtasks.exe /Change /DISABLE /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
)

:: A worthless security measure, just use disk encryption
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
:: After downloading a file, assume it's also going to be ran; don't block it from running
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f

:: https://winaero.com/disable-timeline-windows-10-group-policy/
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
:: Disable Windows Firewall, since Windows Filtering Platform (WFP) is better
netsh.exe advfirewall set allprofiles state off

:: Aero Shake is a bad feature
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f

:: Use old battery flyout, makes it more difficult to accidentally screw up the power options
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseWin32BatteryFlyout" /t REG_DWORD /d 1 /f
:: Use old volume flyout, makes it easier to quickly change advanced settings of the current audio device
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v "EnableMtcUvc" /t REG_DWORD /d 0 /f
:: Enable additional BSOD details
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d 1 /f
:: Disable all Content Delivery Manager features
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
:: For a mouse, extra window top-bar border width is counter intuitive
reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "PaddedBorderWidth" /t REG_SZ /d 0 /f
:: Ensure audio ducking/audio attenuation is disabled
reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f
reg.exe delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore" /f

reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg.exe add "HKCU\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f


if %disable_geolocation%==1 (
	sc.exe stop lfsvc
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
)
if %remove_xbox%==1 (
	sc.exe stop xbgm
	sc.exe stop XblAuthManager
	sc.exe stop XblGameSave
	sc.exe stop XboxGipSvc
	sc.exe stop XboxNetApiSvc
	reg.exe add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d 4 /f
	schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable

	taskkill /im GameBarPresenceWriter.exe /f
	takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
	icacls.exe "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
	move "%WinDir%\System32\GameBarPresenceWriter.exe" "%WinDir%\System32\GameBarPresenceWriter.exe.disabled"
)
if %disable_printer_support%==1 (
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d 4 /f
)
if %disable_bluetooth_audio_support%==1 (
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d 4 /f
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d 4 /f
)
if %run_markc_mousefix%==1 (
	start /wait "" "%~dp0\Symantec\noscript.exe" /silent /off
	start "" WScript.exe "%~dp0\MarkC_MouseFix\MarkC_Windows_10+8.x+7+Vista+XP_MouseFix_Builder.vbs"
)
if %z-disable_script_host%==1 (
	start /wait "" "%~dp0\Symantec\noscript.exe" /silent /on
)

:: Turn off Game DVR; gets rid of "You'll need a new app to open this ms-gamingoverlay" on LTSC 2019
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f

:: TODO: Move this somewhere else
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameUX" /v "DownloadGameInfo" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f

:: Can't test complete Game DVR removal on Windows 10 LTSC 2019 
	::takeown /f "%WinDir%\System32\bcastdvruserservice.dll" /a
	::icacls.exe "%WinDir%\System32\bcastdvruserservice.dll" /grant:r Administrators:F /c
	::move "%WinDir%\System32\bcastdvruserservice.dll" "%WinDir%\System32\bcastdvruserservice.dll.disabled"
	::takeown /f "%WinDir%\SysWOW64\bcastdvruserservice.dll" /a
	::icacls.exe "%WinDir%\SysWOW64\bcastdvruserservice.dll" /grant:r Administrators:F /c
	::move "%WinDir%\SysWOW64\bcastdvruserservice.dll" "%WinDir%\SysWOW64\bcastdvruserservice.dll.disabled"

:: Don't log events without warnings or errors
auditpol.exe /set /category:* /Success:disable

:: Game scheduler tweaks; doubles GPU priority, then sets I/O and CPU priority to High
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 16 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f

:: Works without issue these days on 1809 (LTSC 2019) or newer
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f

:: Don't delay startup of programs
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "Startupdelayinmsec" /t REG_DWORD /d 0 /f
:: Decrease shutdown time
reg.exe add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeOut /t REG_SZ /d 2000 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v HungAppTimeout /t REG_SZ /d 2000 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v AutoEndTasks /t REG_SZ /d 1 /f

:: Don't download Microsoft's Malicious Removal Tool automatically
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
:: Disable Start Menu's Live Tiles
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f
:: Hide News and Interests icon on Windows 10 taskbar
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f
:: Disable first sign-in animation (initiates on a new user account)
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f

:: Clean out font cache; incase font cache was corrupted before running this script
:FontCache
sc stop "FontCache"
:: sc config "FontCache" start=disabled
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d 4 /f
sc query FontCache | findstr /I /C:"STOPPED" 
if not %errorlevel%==0 (goto FontCache)

:: Grant access rights to current user for "%WinDir%\ServiceProfiles\LocalService" folder and contents
icacls.exe "%WinDir%\ServiceProfiles\LocalService" /grant "%UserName%":F /C /T /Q
:: Delete font cache
del /A /F /Q "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*FontCache*"
del /A /F /Q "%WinDir%\System32\FNTCACHE.DAT"

:: sc config "FontCache" start=auto
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d 2 /f

taskkill.exe /IM explorer.exe /F
start explorer.exe
echo.
echo Your PC will restart after a key is pressed; required to fully apply changes
echo.
Pause
shutdown.exe /r /t 00