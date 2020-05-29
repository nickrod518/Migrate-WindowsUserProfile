# Default configuration options - make edits here

# Default domain to use for profile creation
$DefaultDomain = 'DOMAIN'

# Default accounts to exclude from migration in the form of "Domain\UserName"
$DefaultExcludeProfile = @(
    "$env:COMPUTERNAME\default*",
    "NT Service\*"
)

# By default local accounts that don't exist on the new computer will not be created for security measures
# To create these accounts set this to true
$DefaultLACreate = $false

# By default local accounts that are created from the previous option will be disabled for security measures
# To enable these accounts set this to true
$DefaultLACEnable = $false

# Default password for accounts created by previous two options
$DefaultLAPassword = 'P@ssw0rd!'

# Use this to disallow migrations on IP's other than what's specified
$ValidIPAddress = '*'

# Path to store the migration data on the new computer, directory will be created if it doesn't exist
$MigrationStorePath = 'C:\TEMP\MigrationStore'

# Default save remotely option
$DefaultSaveRemotely = $true

# Default user profile items to exclude from migration, more info found here:
# https://technet.microsoft.com/en-us/library/cc722303(v=ws.10).aspx
$DefaultIncludeAppData = $true
$DefaultIncludeLocalAppData = $false
$DefaultIncludePrinters = $true
$DefaultIncludeRecycleBin = $false
$DefaultIncludeMyDocuments = $true
$DefaultIncludeWallpapers = $true
$DefaultIncludeDesktop = $true
$DefaultIncludeDownloads = $true
$DefaultIncludeFavorites = $true
$DefaultIncludeMyMusic = $true
$DefaultIncludeMyPictures = $true
$DefaultIncludeMyVideo = $true

<# Default extra directories to include (all file types)
Example:

This will include the listed paths with all files inside C:\Folder1 
and C:\Folder2\SubFolder recursively.

$DefaultExtraDirectories = @("C:\Folder1", "C:\Folder2\SubFolder")
#>
$DefaultExtraDirectories = @()

<# Default extra file patterns to include (global)
Example:

This will include all PST files, anything that starts with Sample 
and any files named Outlook.txt

$DefaultExtraFiles = @("*.pst", "Sample*", "Outlook.txt") #>
$DefaultExtraFiles = @()

<# Default extra file patterns to exclude (global)
Example:

This will exclude all PST files, anything that starts with Sample 
and any files named Outlook.txt

$DefaultExcludeFiles = @("*.pst", "Sample*", "Outlook.txt") #>
$DefaultExcludeFiles = @()

# Default value for SaveStateTaskCompleted on the Restore Tab
$DefaultSaveStateTaskCompleted = $true

# Default recent profiles
$DefaultRecentProfiles = $true
$DefaultRecentProfilesDays = 90

# Get USMT binary path according to OS architecture. If you used the zip provided, unzip in the same directory as this script
$Arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
if ($Arch -match '64') {
    $USMTPath = "$ScriptRoot\USMT\amd64"
} elseif (($Arch -match '86') -or ($Arch -match '32')) {
    $USMTPath = "$ScriptRoot\USMT\x86"
}
else {
    $USMTPath = "$ScriptRoot\USMT\arm64"
}

# Define whether to continue on errors such as file already exists during restore or read issue during capture.
$ContinueOnError = $true

<# Define the level of verbosity for the USMT scan/load commands
0 Only the default errors and warnings are enabled.
1 Enables verbose output.
4 Enables error and status output.
5 Enables verbose and status output.
8 Enables error output to a debugger.
9 Enables verbose output to a debugger.
12 Enables error and status output to a debugger.
13 Enables verbose, status, and debugger output. #>
$VerboseLevel = 13

# Define wether to hide the powershell window. If you call from ISE it will always not hide
$HidePowershellWindow = $true

# Define how to handle EFS format files. Options are abort (default behaviour), skip, decryptcopy, copyraw
$EFSHandling = "abort"

# Users to additionally send every migration result to
$DefaultEmailEnabled = $false
$DefaultEmailSender = 'MigrationAlert@company.com'
$DefaultEmailRecipients = @('my.email@company.com')
$DefaultSMTPServer = 'smtp.domain.local'

# LastLogin query when gathering profiles - disabling will speed up profile search
$QueryLastLogon = $false
