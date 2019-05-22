[CmdletBinding()]

param(
    [Parameter(Mandatory = $false)]
    [ValidateScript( {
            if ((Get-Item $_).Extension -ne '.MIG') {
                throw "[$_] is not a USMT migration file (mig)."
            }
            else { $true }
        })]
    [string]$MigPath
)

$CurrentID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentID)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $WindowsPrincipal.IsInRole($AdminRole)) {
    $NewProcess = New-Object System.Diagnostics.ProcessStartInfo 'PowerShell'
    $NewProcess.Arguments = $MyInvocation.MyCommand.Definition
    $NewProcess.Verb = 'RunAs'
    [System.Diagnostics.Process]::Start($NewProcess)

    exit
}

# Get USMT binary path according to OS architecture
$arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
if ($arch -match '64') {
    $usmtPath = "$PSScriptRoot\USMT\amd64"
} elseif ($arch -match '86') {
    $usmtPath = "$PSScriptRoot\USMT\x86"
}
else {
    $usmtPath = "$PSScriptRoot\USMT\arm64"
}

if ([string]::IsNullOrEmpty($MigPath)) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Select a USMT migration file to expand"
    $OpenFileDialog.Filter = "MIG (*.MIG)| *.MIG"
    $OpenFileDialog.ShowHelp = $true
    $OpenFileDialog.ShowDialog() | Out-Null
    $MigPath = Get-Item $OpenFileDialog.FileName
}

$destination = Split-Path $MigPath -Parent

try {
    Start-Process -FilePath "$usmtPath\usmtutils.exe" -ArgumentList "/extract `"$MigPath`" `"$destination`"" -Wait -NoNewWindow
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
}

pause