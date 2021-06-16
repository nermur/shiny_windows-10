# List all possible power config GUIDs in Windows
# Run: this-script.ps1 | Out-File powercfg.ps1
# Then edit and run powercfg.ps1
# (c) Pekka "raspi" Järvinen 2017
# Modified by andmade 2019

$powerSettingTable = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerSetting
$powerSettingInSubgroubTable = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerSettingInSubgroup

Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerSettingCapabilities | ForEach-Object {
  $tmp = $_.ManagedElement
  $tmp = $tmp.Remove(0, $tmp.LastIndexOf('{') + 1)
  $tmp = $tmp.Remove($tmp.LastIndexOf('}'))
  
  $guid = $tmp

  $s = ($powerSettingInSubgroubTable | Where-Object PartComponent -Match "$guid")

  if (!$s) {
    return
  }
  
  $tmp = $s.GroupComponent
  $tmp = $tmp.Remove(0, $tmp.LastIndexOf('{') + 1)
  $tmp = $tmp.Remove($tmp.LastIndexOf('}'))
  
  $groupguid = $tmp
  
  $s = ($powerSettingTable | Where-Object InstanceID -Match "$guid")
  
  $descr = [string]::Format("# {0}", $s.ElementName)
  $runcfg = [string]::Format("Set-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\Power\PowerSettings\{0}\{1} -Name Attributes -Value 2", $groupguid, $guid)
  
  Write-Output $descr
  Write-Output $runcfg
  Write-Output ""
  Invoke-Expression $runcfg 
}