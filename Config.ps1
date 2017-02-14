# Default configuration options - make edits here

# Default domain to use for profile creation
$DefaultDomain = 'DOMAIN'

# Verify that the user running this script has this extension in their username to ensure admin rights
$AdminExtension = '-admin'

# Default accounts to exclude from migration in the form of "Domain\UserName"
$DefaultExcludeProfile = @(
    "$ENV:Computername\default*",
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

# Default user profile items to exclude from migration, more info found here: 
# https://technet.microsoft.com/en-us/library/cc722303(v=ws.10).aspx
$DefaultIncludeAppData = $true
$DefaultIncludeLocalAppData = $false
$DefaultIncludePrinters = $true
$DefaultIncludeRecycleBin = $false
$DefaultIncludeMyDocuments = $true
$DefaultIncludeWallpapers = $true
$DefaultIncludeDesktop = $true
$DefaultIncludeFavorites = $true
$DefaultIncludeMyMusic = $true
$DefaultIncludeMyPictures = $true
$DefaultIncludeMyVideo = $true

# Get USMT binary path according to OS architecture. If you used the zip provided, unzip in the same directory as this script
if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') { 
    $USMTPath = "$ScriptRoot\USMT\amd64"
} else { 
    $USMTPath = "$ScriptRoot\USMT\x86"
}

# Define whether to continue on errors such as file allready exists during restore or read issue during capture.
$ContinueOnError = $True

# Define options for encypting the migration files files - set this to $True or $False
$UseEncryption = $False
$EncryptionString = 'P@ssw0rd!'

# Users to additionially send every migration result to
$DefaultEmailEnabled = $false
$DefaultEmailSender = 'MigrationAlert@company.com'
$DefaultEmailRecipients = @('my.email@company.com')
$DefaultSMTPServer = 'smtp.domain.local'

# LastLogin query when gathering profiles - disabling will speed up profile search
$QueryLastLogon = $false