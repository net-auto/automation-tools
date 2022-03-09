
<#

Description:
powershell script for synchronisation of the NPS config between two NPS services.
You need to define a "logical" master node as primary and perform the changed only on that node.

Note:
- if needed change the variables to fit your needs
- copy/import transaction will only be performed, if the filesize of the config has changed on the "master" node

Task Scheduler usage:
- tick the option: "run with highest priviledge"
- use the command: "powershell.exe -NoProfile -NoLogo -NonInteractive -File \\path\to\script\nps_config_sync.ps1"


#>

Function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
       #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess)
 
       #Exit from the current, unelevated, process
       Exit
 
    }
}
 
#Check Script is running with Elevated Privileges
Check-RunAsAdministrator
 
# variables:
$date = get-date -Format yyyy_MM_dd

# set the destination/backup NPS server hostname/IP
$NPSDestServer = "BACKUP_IP_SERVERNAME_OR_IP"

# customize this path to fit your needs!:
$backupDir = "C:\backup\NPS\TEMP_CONFIG_FILES"

$filePathDate = "$($backupDir)\NPSConfig_$($date).xml"
$filePathLocalConfig = "$($backupDir)\NPSConfig.xml"
$fileDestinationUnc = "\\$NPSDestServer\C$\backup\NPS\NPSConfig.xml"
$fileDestinationBackup = "$($backupDir)\BackupNPSConfig.xml"
#

$FolderName = $backupDir
if (Test-Path $FolderName) {
   
    Write-Host "Folder: $backupDir exists"

    Write-Host "DELETE CONFIG FILES OLDER THEN 60 DAYS AT THE DIRECTORY: $backupDir ..."
    # Delete all Files in $backupDir older than 60 day(s)
    $Path = $backupDir
    $Daysback = "-60"
 
    $CurrentDate = Get-Date
    $DatetoDelete = $CurrentDate.AddDays($Daysback)
    Get-ChildItem $Path | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item
}
else
{
  
    #PowerShell Create directory if not exists
    New-Item $FolderName -ItemType Directory
    Write-Host "Folder Created successfully"

}

# Export NPS config:
Export-NpsConfiguration -Path $filePathDate
Export-NpsConfiguration -Path $filePathLocalConfig
#
# Copy local config to destination server:
Copy-Item -path $filePathLocalConfig -destination $fileDestinationUnc

# export/backup current config at remote destination:
Invoke-Command -ComputerName $NPSDestServer -ScriptBlock {Export-NPSConfiguration -Path $Using:fileDestinationBackup}

# get file size of the exported local config and convert to KB:
$fileSizeExportedLocalConfig = (Get-Item $filePathLocalConfig).Length/1KB

# get file size of the exported config at the destination server and convert to KB:
$fileSizeExportedRemoteConfig = Invoke-Command -ComputerName $NPSDestServer -ScriptBlock {(Get-Item $Using:fileDestinationBackup).Length/1KB}

# compare the file size of local and remote config and save the result to var:
$filesizeIsEqual = $fileSizeExportedLocalConfig -eq $fileSizeExportedRemoteConfig

# if $filesizeIsEqual is not true (false), import the config at the remote destination:
if ( -not ($filesizeIsEqual) )
{
    Write-Host "IMPORTING CONFIG AT $NPSDestServer"
    Invoke-Command -ComputerName $NPSDestServer -ScriptBlock {Import-NPSConfiguration -Path $Using:filePathLocalConfig}
    Write-Host "CONFIG IMPORTED AT $NPSDestServer"
}
else {
    Write-Host "CONFIG IS EQUAL"
}


