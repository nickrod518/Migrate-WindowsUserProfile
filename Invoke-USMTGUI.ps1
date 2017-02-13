<#
.SYNOPSIS
    Migrate user state from one PC to another using USMT.

.DESCRIPTION
    Migrate user state from one PC to another using USMT. Intended for domain joined computers.
    By default, all user profile data except Favorites and Documents will be included.
    Tool also allows for user to specify additional folders to include.

.NOTES
    USMT environmental variables: https://technet.microsoft.com/en-us/library/cc749104(v=ws.10).aspx

#>

begin {
    # Set ScripRoot variable to the path which the script is executed from.
    $PSScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path

	###################################################################################################################
    # Default configuration options - make edits starting here

	# Default domain to use for profile creation
    $Script:DefaultDomain = 'DOMAIN'

	# Verify that the user running this script has this extension in their username to ensure admin rights
    $Script:AdminExtension = '-admin'

    # Default accounts to exclude from migration in the form of "Domain\UserName"
    $Script:DefaultExcludeProfile = @(
        "$ENV:Computername\default*",
        "NT Service\*"
    )

    # By default local accounts that don't exist on the new computer will not be created for security measures
    # To create these accounts set this to true
    $Script:DefaultLACreate = $false

    # By default local accounts that are created from the previous option will be disabled for security measures
    # To enable these accounts set this to true
    $Script:DefaultLACEnable = $false

    # Default password for accounts created by previous two options
    $Script:DefaultLAPassword = 'P@ssw0rd!'

	# Use this to disallow migrations on IP's other than what's specified
    $Script:ValidIPAddress = '*'

	# Path to store the migration data on the new computer, directory will be created if it doesn't exist
    $Script:MigrationStorePath = 'C:\TEMP\MigrationStore'

	# Default user profile items to exclude from migration, more info found here: 
	# https://technet.microsoft.com/en-us/library/cc722303(v=ws.10).aspx
    $Script:DefaultIncludeAppData = $true
    $Script:DefaultIncludeLocalAppData = $true
    $Script:DefaultIncludePrinters = $true
    $Script:DefaultIncludeRecycleBin = $false
    $Script:DefaultIncludeMyDocuments = $true
    $Script:DefaultIncludeWallpapers = $true
    $Script:DefaultIncludeDesktop = $true
    $Script:DefaultIncludeFavorites = $true
    $Script:DefaultIncludeMyMusic = $true
    $Script:DefaultIncludeMyPictures = $true
    $Script:DefaultIncludeMyVideo = $true
	
	# Get USMT binary path according to OS architecture. If you used the zip provided, unzip in the same directory as this script
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') { 
        $Script:USMTPath = "$PSScriptRoot\USMT\amd64"
    } else { 
        $Script:USMTPath = "$PSScriptRoot\USMT\x86"
    }

    #Define whether to continue on errors such as file allready exists during restore or read issue during capture.
    $ContinueOnError = $True

	#Define options for encypting the migration files files.
	#Set this to $True or $False
	$UseEncryption = $False
	$EncryptionString = 'P@ssw0rd!'

    # Users to additionially send every migration result to
    $Script:DefaultEmailEnabled = $false
    $Script:DefaultEmailSender = 'MigrationAlert@company.com'
    $Script:DefaultEmailRecipients = @('my.email@company.com')
    $Script:DefaultSMTPServer = 'smtp.domain.local'

    # LastLogin query when gathering profiles - disabling will speed up profile search
    $Script:QueryLastLogon = $false
    
	# End of configuration options - make no edits past this
	###################################################################################################################

    # Define the script version.
    $ScriptVersion = 2.8

    function Update-Log {
        param(
            [string] $Message,

            [string] $Color = 'White',

            [switch] $NoNewLine
        )

        $LogTextBox.SelectionColor = $Color
        $LogTextBox.AppendText("$Message")
        if (-not $NoNewLine) { $LogTextBox.AppendText("`n") }
        $LogTextBox.Update()
        $LogTextBox.ScrollToCaret()
    }

    function Read-EncryptionPassword {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        $computer = [Microsoft.VisualBasic.Interaction]::InputBox("Enter password to encrypt the migration file", "Password", "$Script:EncryptionString")
    }

    function Get-IPAddress { (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString }

    # Get the host name the script is running from
    function Get-HostName { $env:COMPUTERNAME }

    # Get the user's name that ran this script
    function Get-CurrentUserName { $env:USERNAME }

    function Get-UserProfileLastLogin {
        param(
            [string]$Domain,
            [string]$UserName
        )

        $CurrentUser = try { ([ADSI]"WinNT://$Domain/$UserName") } catch { }
        if ($CurrentUser.Properties.LastLogin) {
            try {
                [datetime](-join $CurrentUser.Properties.LastLogin)
            } catch {
                -join $CurrentUser.Properties.LastLogin
            }
        } elseif ($CurrentUser.Properties.Name) {
        } else {
            'N/A'
        }
    }

    function Get-UserProfiles {
        # Get all user profiles on this PC and let the user select which ones to migrate
        $RegKey = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

        # Return each profile on this computer
        Get-ItemProperty -Path $RegKey | ForEach-Object {
            try {
                $SID = New-object System.Security.Principal.SecurityIdentifier($_.PSChildName)
                try {

                    $User = $SID.Translate([System.Security.Principal.NTAccount]).Value

                    # Don't show NT Authority accounts
                    if ($User -notlike 'NT Authority\*') {
                        $Domain = $User.Split('\')[0]
                        $UserName = $User.Split('\')[1]
                        if ($Script:QueryLastLogon) {
                            $LastLogin = Get-UserProfileLastLogin -Domain $Domain -UserName $UserName
                        } else {
                            $LastLogin = 'N/A'
                        }
                        $ProfilePath = Get-UserProfilePath -Domain $Domain -UserName $UserName

                        $UserObject = New-Object psobject
                        $UserObject | Add-Member -MemberType NoteProperty -Name Domain -Value $Domain
                        $UserObject | Add-Member -MemberType NoteProperty -Name UserName -Value $UserName
                        $UserObject | Add-Member -MemberType NoteProperty -Name LastLogin -Value $LastLogin
                        $UserObject | Add-Member -MemberType NoteProperty -Name ProfilePath -Value $ProfilePath

                        $UserObject
                    }
                } catch {
                    Update-Log "Error while translating $SID to a user name." -Color 'Yellow'
                }
            } catch {
                Update-Log "Error while translating $($_.PSChildName) to SID." -Color 'Yellow'
            }
        }
    }

    function Get-UserProfilePath {
        param(
            [string]$Domain,
            [string]$UserName
        )

        $UserObject = New-Object System.Security.Principal.NTAccount($Domain, $UserName) 
        $SID = $UserObject.Translate([System.Security.Principal.SecurityIdentifier])
        $User = Get-ItemProperty -Path "Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID.Value)"
        $User.ProfileImagePath
    }

    function Test-UserAdmin {
        if (-not ($(Get-CurrentUserName) -like "*$AdminExtension")) {
            Update-Log "You are running this script with user account $(Get-CurrentUserName), which is not a $AdminExtension account. " -Color 'Red' -NoNewLine
            Update-Log "Some tasks may fail if not run with admin credentials.`n" -Color 'Red'
        }
    }

    function Set-SaveDirectory {
        param (
            [Parameter(Mandatory = $true)]
            [ValidateSet('Destination', 'Source')] 
            [string] $Type
        )

        # Bring up file explorer so user can select a directory to add
        $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
        $OpenDirectoryDialog.RootFolder = 'Desktop'
        $OpenDirectoryDialog.SelectedPath = $SaveDestinationTextBox.Text
        if ($Type -eq 'Destination') {
            $OpenDirectoryDialog.SelectedPath = $SaveDestinationTextBox.Text
        } else {
            $OpenDirectoryDialog.SelectedPath = $SaveSourceTextBox.Text
        }
        $OpenDirectoryDialog.ShowDialog() | Out-Null
        $SelectedDirectory = $OpenDirectoryDialog.SelectedPath
        try {
            # If user hits cancel it could cause attempt to add null path, so check that there's something there
            if ($SelectedDirectory) {
                Update-Log "Changed save directory to [$SelectedDirectory]."
                if ($Type -eq 'Destination') {
                    $SaveDestinationTextBox.Text = $SelectedDirectory
                } else {
                    $SaveSourceTextBox.Text = $SelectedDirectory
                }
            }
        } catch {
            Update-Log "There was a problem with the directory you chose: $($_.Exception.Message)" -Color Red
        }
    }

    function Add-ExtraDirectory {
        # Bring up file explorer so user can select a directory to add
        $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
        $OpenDirectoryDialog.RootFolder = 'Desktop'
        $OpenDirectoryDialog.SelectedPath = 'C:\'
        $Result = $OpenDirectoryDialog.ShowDialog()
        $SelectedDirectory = $OpenDirectoryDialog.SelectedPath
        try {
            # If user hits cancel don't add the path
            if ($Result -eq 'OK') {
                Update-Log "Adding to extra directories: $SelectedDirectory."
                $ExtraDirectoriesDataGridView.Rows.Add($SelectedDirectory)
            } else {
                Update-Log "Add directory action cancelled by user." -Color Yellow
            }
        } catch {
            Update-Log "There was a problem with the directory you chose: $($_.Exception.Message)" -Color Red
        }
    }

    function Remove-ExtraDirectory {
        # Remove selected cell from Extra Directories data grid view
        $CurrentCell = $ExtraDirectoriesDataGridView.CurrentCell
        Update-Log "Removed [$($CurrentCell.Value)] from extra directories."
        $CurrentRow = $ExtraDirectoriesDataGridView.Rows[$CurrentCell.RowIndex]
        $ExtraDirectoriesDataGridView.Rows.Remove($CurrentRow)
    }

    function Set-Config {
        $ExtraDirectoryCount = $ExtraDirectoriesDataGridView.RowCount

        if ($ExtraDirectoryCount) {
            Update-Log "Including $ExtraDirectoryCount extra directories."

            $ExtraDirectoryXML = @"
    <!-- This component includes the additional directories selected by the user -->
    <component type="Documents" context="System">
        <displayName>Additional Folders</displayName>
        <role role="Data">
            <rules>
                <include>
                    <objectSet>

"@
            # Include each directory user has added to the Extra Directories data grid view
            $ExtraDirectoriesDataGridView.Rows | ForEach-Object {
                $CurrentRowIndex = $_.Index
                $Path = $ExtraDirectoriesDataGridView.Item(0, $CurrentRowIndex).Value

                $ExtraDirectoryXML += @"
                        <pattern type=`"File`">$Path\* [*]</pattern>"

"@
            }

            $ExtraDirectoryXML += @"
                    </objectSet>
                </include>
            </rules>
        </role>
    </component>
"@
        } else {
            Update-Log 'No extra directories will be included.'
        }
        
        Update-Log 'Data to be included:'
        foreach ($Control in $InclusionsGroupBox.Controls) { if ($Control.Checked) { Update-Log $Control.Text } }

        $ExcludedDataXML = @"
            $(
                if (-not $IncludePrintersCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_PRINTERS%\* [*]</pattern>`n" }
                if (-not $IncludeRecycleBinCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_BITBUCKET%\* [*]</pattern>`n" }
                if (-not $IncludeMyDocumentsCheckBox.Checked) {
                    "<pattern type=`"File`">%CSIDL_MYDOCUMENTS%\* [*]</pattern>`n"
                    "<pattern type=`"File`">%CSIDL_PERSONAL%\* [*]</pattern>`n"
                }
                if (-not $IncludeDesktopCheckBox.Checked) {
                    "<pattern type=`"File`">%CSIDL_DESKTOP%\* [*]</pattern>`n"
                    "<pattern type=`"File`">%CSIDL_DESKTOPDIRECTORY%\* [*]</pattern>`n"
                }
                if (-not $IncludeFavoritesCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_FAVORITES%\* [*]</pattern>`n" }
                if (-not $IncludeMyMusicCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_MYMUSIC%\* [*]</pattern>`n" }
                if (-not $IncludeMyPicturesCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_MYPICTURES%\* [*]</pattern>`n" }
                if (-not $IncludeMyVideoCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_MYVIDEO%\* [*]</pattern>`n" }
            )
"@

        $AppDataXML = if ($IncludeAppDataCheckBox.Checked) {
            @"
            <!-- This component migrates all user app data -->
            <component type=`"Documents`" context=`"User`">
                <displayName>App Data</displayName>
                <paths>
                    <path type="File">%CSIDL_APPDATA%</path>
                </paths>
                <role role="Data">
                    <detects>
                        <detect>
                            <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_APPDATA%")</condition>
                        </detect>
                    </detects>
                    <rules>
                        <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                            <objectSet>
                                <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                            </objectSet>
                        </include>
                        <merge script='MigXmlHelper.DestinationPriority()'>
                            <objectSet>
                                <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                            </objectSet>
                        </merge>
                    </rules>
                </role>
            </component>
"@
        }

        $LocalAppDataXML = if ($IncludeLocalAppDataCheckBox.Checked) {
            @"
            <!-- This component migrates all user local app data -->
            <component type=`"Documents`" context=`"User`">
                <displayName>Local App Data</displayName>
                <paths>
                    <path type="File">%CSIDL_LOCAL_APPDATA%</path>
                </paths>
                <role role="Data">
                    <detects>
                        <detect>
                            <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_LOCAL_APPDATA%")</condition>
                        </detect>
                    </detects>
                    <rules>
                        <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                            <objectSet>
                                <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                            </objectSet>
                        </include>
                        <merge script='MigXmlHelper.DestinationPriority()'>
                            <objectSet>
                                <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                            </objectSet>
                        </merge>
                    </rules>
                </role>
            </component>
"@
        }

        $WallpapersXML = if ($IncludeWallpapersCheckBox.Checked) {
            @"
            <!-- This component migrates wallpaper settings -->
            <component type="System" context="User">
                <displayName>Wallpapers</displayName>
                <role role="Settings">
                    <rules>
                        <include>
                            <objectSet>
                                <pattern type="Registry">HKCU\Control Panel\Desktop [Pattern]</pattern>
                                <pattern type="Registry">HKCU\Control Panel\Desktop [PatternUpgrade]</pattern>
                                <pattern type="Registry">HKCU\Control Panel\Desktop [TileWallpaper]</pattern>
                                <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                                <pattern type="Registry">HKCU\Control Panel\Desktop [WallpaperStyle]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Windows\CurrentVersion\Themes [SetupVersion]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [TileWallpaper]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperFileTime]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperLocalFileTime]</pattern>
                                <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperStyle]</pattern>
                                <content filter="MigXmlHelper.ExtractSingleFile(NULL, NULL)">
                                    <objectSet>
                                        <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                                        <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                                        <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                                    </objectSet>
                                </content>
                            </objectSet>
                        </include>
                    </rules>
                </role>
            </component>

            <!-- This component migrates wallpaper files -->
            <component type="Documents" context="System">
                <displayName>Move JPG and BMP</displayName>
                <role role="Data">
                    <rules>
                        <include>
                            <objectSet>
                                <pattern type="File"> %windir% [*.bmp]</pattern>
                                <pattern type="File"> %windir%\web\wallpaper [*.jpg]</pattern>
                                <pattern type="File"> %windir%\web\wallpaper [*.bmp]</pattern>
                            </objectSet>
                        </include>
                    </rules>
                </role>
            </component>
"@
}

        $ConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<migration urlid="http://www.microsoft.com/migration/1.0/migxmlext/config">
    <_locDefinition>
        <_locDefault _loc="locNone"/>
        <_locTag _loc="locData">displayName</_locTag>
    </_locDefinition>

$ExtraDirectoryXML

    <!-- This component migrates all user data except specified exclusions -->
    <component type="Documents" context="User">
        <displayName>Documents</displayName>
        <role role="Data">
            <rules>
                <include filter="MigXmlHelper.IgnoreIrrelevantLinks()">
                    <objectSet>
                        <script>MigXmlHelper.GenerateDocPatterns ("FALSE","TRUE","FALSE")</script>
                    </objectSet>
                </include>
                <exclude filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                    <objectSet>
                        <script>MigXmlHelper.GenerateDocPatterns ("FALSE","FALSE","FALSE")</script>
                    </objectSet>
                </exclude>
                <exclude>
                    <objectSet>
$ExcludedDataXML
                    </objectSet>
                </exclude>
                <contentModify script="MigXmlHelper.MergeShellLibraries('TRUE','TRUE')">
                    <objectSet>
                        <pattern type="File">*[*.library-ms]</pattern>
                    </objectSet>
                </contentModify>
                <merge script="MigXmlHelper.SourcePriority()">
                    <objectSet>
                        <pattern type="File">*[*.library-ms]</pattern>
                    </objectSet>
                </merge>
            </rules>
        </role>
    </component>

$AppDataXML

$LocalAppDataXML

$WallpapersXML

</migration>
"@

        $Config = "$Destination\Config.xml"
        try {
            New-Item $Config -ItemType File -Force -ErrorAction Stop | Out-Null
        } catch {
            Update-Log "Error creating config file [$Config]: $($_.Exception.Message)" -Color 'Red'
            return
        }
        try {
            Set-Content $Config $ConfigContent -ErrorAction Stop
        } catch {
            Update-Log "Error while setting config file content: $($_.Exception.Message)" -Color 'Red'
            return
        }

        # Return the path to the config
        $Config
    }

    function Get-USMT {
        # Test that USMT binaries are reachable
        if (Test-Path $USMTPath) {
            $Script:ScanState = "$USMTPath\scanstate.exe"
            $Script:LoadState = "$USMTPath\loadstate.exe"
			Update-Log "Using [$USMTPath] as path to USMT binaries."
        } else {
            Update-Log "Unable to reach USMT binaries. Verify [$USMTPath] exists and restart script.`n" -Color 'Red'
            $MigrateButton_OldPage.Enabled = $false
            $MigrateButton_NewPage.Enabled = $false
        }
    }

    function Get-USMTResults {
        param([string] $ActionType)

        if ($PSVersionTable.PSVersion.Major -lt 3) {
            # Print back the entire log
            $Results = Get-Content "$Destination\$ActionType.log" | Out-String
        } else {
            # Get the last 4 lines from the log so we can see the results
            $Results = Get-Content "$Destination\$ActionType.log" -Tail 4 | ForEach-Object { 
                ($_.Split(']', 2)[1]).TrimStart()
            } | Out-String
        }

        Update-Log $Results -Color 'Cyan'

		if ($ActionType -eq 'load') {
			Update-Log 'A reboot is recommended.' -Color 'Yellow'
        
            $EmailSubject = "Migration Load Results of $($OldComputerNameTextBox_NewPage.Text) to $($NewComputerNameTextBox_NewPage.Text)"
		} else {
            $EmailSubject = "Migration Save Results of $($OldComputerNameTextBox_OldPage.Text) to $($NewComputerNameTextBox_OldPage.Text)"
        }

        if ($EmailCheckBox.Checked) {
            if ($SMTPConnectionCheckBox.Checked -or (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
                $SMTPConnectionCheckBox.Checked = $true

                $EmailRecipients = @()

                $EmailRecipientsDataGridView.Rows | ForEach-Object {
                    $CurrentRowIndex = $_.Index
                    $EmailRecipients += $EmailRecipientsDataGridView.Item(0, $CurrentRowIndex).Value
                }

                Update-Log "Emailing migration results to: $EmailRecipients"

                try {
                    Send-MailMessage -From $EmailSenderTextBox.Text -To $EmailRecipients `
                        -Subject $EmailSubject -Body $LogTextBox.Text -SmtpServer $SMTPServerTextBox.Text `
                        -Attachments "$Destination\$ActionType.log"
                } catch {
                    Update-Log "Error occurred sending email: $($_.Exception.Message)" -Color 'Red'
                }
            } else {
                Update-Log "Unable to send email of results because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
            }
        }
    }

    function Get-USMTProgress {
        param(
            [string] $Destination,

            [string] $ActionType
        )

        try {
            # Get the most recent entry in the progress log
            $LastLine = Get-Content "$Destination\$($ActionType)_progress.log" -Tail 1 -ErrorAction SilentlyContinue | Out-String
            Update-Log ($LastLine.Split(',', 4)[3]).TrimStart()
        } catch { Update-Log '.' -NoNewLine }
    }

    function Get-SaveState {
        # Use the migration folder name to get the old computer name
        if (Get-ChildItem $SaveSourceTextBox.Text -ErrorAction SilentlyContinue) {
            $SaveSource = Get-ChildItem $SaveSourceTextBox.Text | Where-Object { $_.PSIsContainer } | 
                Sort-Object -Descending -Property { $_.CreationTime } | Select-Object -First 1
            if (Test-Path "$($SaveSource.FullName)\USMT\USMT.MIG") {
                $Script:UncompressedSource = $false
            } else {
                $Script:UncompressedSource = $true
                Update-Log -Message "Uncompressed save state detected."
            }
            $OldComputer = $SaveSource.BaseName
            Update-Log -Message "Old computer set to $OldComputer."
        } else {
            $OldComputer = 'N/A'
            Update-Log -Message "No saved state found at [$($SaveSourceTextBox.Text)]." -Color 'Yellow'
        }

        $OldComputer
    }

    function Show-DomainInfo {
        # Populate old user data if DomainMigration.txt file exists, otherwise disable group box
        if (Test-Path "$MigrationStorePath\$($OldComputerNameTextBox_NewPage.Text)\DomainMigration.txt") {
            $OldUser = Get-Content "$MigrationStorePath\$($OldComputerNameTextBox_NewPage.Text)\DomainMigration.txt"
            $OldDomainTextBox.Text = $OldUser.Split('\')[0]
            $OldUserNameTextBox.Text = $OldUser.Split('\')[1]
        } else {
            $CrossDomainMigrationGroupBox.Enabled = $false
            $CrossDomainMigrationGroupBox.Hide()
        }
    }

    function Save-UserState {
        param(
            [switch] $Debug
        )

        Update-Log "`nBeginning migration..."

        # If we're saving locally, skip network stuff
        if ($SaveRemotelyCheckBox.Checked) {
            # If connection hasn't been verfied, test now
            if (-not $ConnectionCheckBox_OldPage.Checked) {
                Test-ComputerConnection -ComputerNameTextBox $NewComputerNameTextBox_OldPage `
                -ComputerIPTextBox $NewComputerIPTextBox_OldPage -ConnectionCheckBox $ConnectionCheckBox_OldPage
            }

            # Try and use the IP if the user filled that out, otherwise use the name
            if ($NewComputerIPTextBox_OldPage.Text -ne '') {
                $NewComputer = $NewComputerIPTextBox_OldPage.Text
            } else {
                $NewComputer = $NewComputerNameTextBox_OldPage.Text
            }
        }

        $OldComputer = $OldComputerNameTextBox_OldPage.Text

        # After connection has been verified, continue with save state
        if ($ConnectionCheckBox_OldPage.Checked -or (-not $SaveRemotelyCheckBox.Checked)) {
            Update-Log 'Connection verified, proceeding with migration...'

            # Get the selected profiles
            if ($RecentProfilesCheckBox.Checked -eq $true) {
                Update-Log "All profiles logged into within the last $($RecentProfilesDaysTextBox.Text) days will be saved."
            } elseif ($Script:SelectedProfile) {
                Update-Log "Profile(s) selected for save state:"
                $Script:SelectedProfile | ForEach-Object { Update-Log $_.UserName }
            } else {
                Update-Log "You must select a user profile." -Color 'Red'
                return
            }

            if (-not $SaveRemotelyCheckBox.Checked) {
                $Script:Destination = "$($SaveDestinationTextBox.Text)\$OldComputer"
            } else {
                # Set destination folder on new computer
                try {
                    $DriveLetter = $MigrationStorePath.Split(':', 2)[0]
                    $MigrationStorePath = $MigrationStorePath.TrimStart('C:\')
                    New-Item "\\$NewComputer\$DriveLetter$\$MigrationStorePath" -ItemType Directory -Force | Out-Null
                    $Script:Destination = "\\$NewComputer\$DriveLetter$\$MigrationStorePath\$OldComputer"
                } catch {
                    Update-Log "Error while creating migration store [$Destination]: $($_.Exception.Message)" -Color 'Yellow'
                    return
                }
            }

            # Create destination folder
            try {
                New-Item $Destination -ItemType Directory -Force | Out-Null
            } catch {
                Update-Log "Error while creating migration store [$Destination]: $($_.Exception.Message)" -Color 'Yellow'
                return
            }

            # If profile is a domain other than $DefaultDomain, save this info to text file
            if ($RecentProfilesCheckBox.Checked -eq $false) {
                $FullUserName = "$($Script:SelectedProfile.Domain)\$($Script:SelectedProfile.UserName)"
                if ($Script:SelectedProfile.Domain -ne $DefaultDomain) {
                    New-Item "$Destination\DomainMigration.txt" -ItemType File -Value $FullUserName -Force | Out-Null
                    Update-Log "Text file created with cross-domain information."
                }
            }

            # Clear encryption syntax in case it's already defined.
            $EncryptionSnytax = ""
            #Determine if Encryption has been requested
			if ($UseEncryption -eq $True){
				#Set the syntax for the encryption
				$EncryptionKey = """$EncryptionString"""
				$EncryptionSnytax = "/encrypt /key:$EncryptionKey"
			}
            
            #Set the value to continue on error if it was specified above
            if ($ContinueOnError -eq $True){
                $ContinueCommand  = "/c"
                }
            if ($ContinueOnError -eq $False){
                $ContinueCommand = ""
            }
			
            
            # Create config syntax for scanstate for custom XMLs.           
            IF ($SelectedXMLS) {
                #Create the scanstate syntax line for the config files.
                foreach ($ConfigXML in $SelectedXMLS) {
                    $ConfigXMLPath = """$Script:USMTPath\$ConfigXML"""
                    $ScanstateConfig += "/i:$ConfigXMLPath "
                 }
            }

            # Create config syntax for scanstate for generated XML.     
            IF (!($SelectedXMLS)){ 
                # Create the scan configuration
                Update-Log 'Generating configuration file...'
                $Config = Set-Config
                $GeneratedConfig = """$Config"""
                $ScanStateConfig = "/i:$GeneratedConfig"
            }

            # Generate parameter for logging
            $Logs = "`"/l:$Destination\scan.log`" `"/progress:$Destination\scan_progress.log`""

            # Set parameter for whether save state is compressed
            if ($UncompressedCheckBox.Checked -eq $true) {
                $Uncompressed = '/nocompress'
            } else {
                $Uncompressed = ''
            }

            # Create a string for all users to exclude by default
            foreach ($ExcludeProfile in $Script:DefaultExcludeProfile) {
                $ExcludeProfile = """$ExcludeProfile"""
                $UsersToExclude += "/ue:$ExcludeProfile "
            }
            

            # Overwrite existing save state, use volume shadow copy method, exclude all but the selected profile(s)
            # Get the selected profiles
            if ($RecentProfilesCheckBox.Checked -eq $true) {
                $Arguments = "`"$Destination`" $ScanStateConfig /o /vsc $UsersToExclude /uel:$($RecentProfilesDaysTextBox.Text) $EncryptionSnytax $Uncompressed $Logs $ContinueCommand "
            } else {
                $UsersToInclude += $Script:SelectedProfile | ForEach-Object { "`"/ui:$($_.Domain)\$($_.UserName)`"" }
                $Arguments = "`"$Destination`" $ScanStateConfig /o /vsc /ue:* $UsersToExclude $UsersToInclude $EncryptionSnytax $Uncompressed $Logs $ContinueCommand "
            }

            # Begin saving user state to new computer
            Update-Log "Command used:"
            Update-Log "$ScanState $Arguments" -Color 'Cyan'

            # If we're running in debug mode don't actually start the process
            if ($Debug) { return }

            Update-Log "Saving state of $OldComputer to $Destination..." -NoNewLine
            Start-Process -FilePath $ScanState -ArgumentList $Arguments -Verb RunAs

            # Give the process time to start before checking for its existence
            Start-Sleep -Seconds 3

            # Wait until the save state is complete
            try {
                $ScanProcess = Get-Process -Name scanstate -ErrorAction Stop
                while (-not $ScanProcess.HasExited) {
                    Get-USMTProgress
                    Start-Sleep -Seconds 3
                }
                Update-Log "Complete!" -Color 'Green'

                Update-Log 'Results:'
                Get-USMTResults -ActionType 'scan'
            } catch {
                Update-Log $_.Exception.Message -Color 'Red'
            }
        }
    }

    function Load-UserState {
        param(
            [switch] $Debug
        )

        Update-Log "`nBeginning migration..."

        # If override is enabled, skip network checks
        if (-not $OverrideCheckBox.Checked) {
            # If connection hasn't been verfied, test now
            if (-not $ConnectionCheckBox_NewPage.Checked) {
                Test-ComputerConnection -ComputerNameTextBox $OldComputerNameTextBox_NewPage `
                -ComputerIPTextBox $OldComputerIPTextBox_NewPage -ConnectionCheckBox $ConnectionCheckBox_NewPage
            }

            # Try and use the IP if the user filled that out, otherwise use the name
            if ($OldComputerIPTextBox_NewPage.Text -ne '') {
                $OldComputer = $OldComputerIPTextBox_NewPage.Text
            } else {
                $OldComputer = $OldComputerNameTextBox_NewPage.Text
            }

            if ($ConnectionCheckBox_NewPage.Checked) {
                Update-Log "Connection verified, checking in with $OldComputer..."

                # Check in with the old computer and don't start until the save is complete
                if (Get-Process -Name scanstate -ComputerName $OldComputer -ErrorAction SilentlyContinue) {
                    Update-Log "Waiting on $OldComputer to complete save state..."
                    while (Get-Process -Name scanstate -ComputerName $OldComputer -ErrorAction SilentlyContinue) {
                        Get-USMTProgress
                        Start-Sleep -Seconds 1
                    }
                } else {
                    Update-Log "Save state process on $OldComputer is complete. Proceeding with migration."
                }
            } else {
                Update-Log "Unable to verify connection with $OldComputer. Migration cancelled." -Color 'Red'
                return
            }
        } else {
            $OldComputer = $OldComputerNameTextBox_NewPage.Text
            Update-Log "User has verified the save state process on $OldComputer is already completed. Proceeding with migration."
        }
		$OldComputerName = $OldComputerNameTextBox_NewPage.Text
        
        # Get the location of the save state data
        $Script:Destination = "$($SaveSourceTextBox.Text)\$OldComputerName"

        # Check that the save state data exists
        if (-not (Test-Path $Destination)) {
            Update-Log "No saved state found at [$Destination]. Migration cancelled." -Color 'Red'
            return
        }
		
            # Clear decryption syntax in case it's already defined.
            $DecryptionSyntax = ""
			#Determine if Encryption has been requested
			if ($UseEncryption -eq $True){
				#Set the syntax for the encryption
				$DecryptionKey = """$EncryptionString"""
				$DecryptionSnytax = "/decrypt /key:$DecryptionKey"
			}
            
            # Set the value to continue on error if it was specified above
            if ($ContinueOnError -eq $True){
                $ContinueCommand  = "/c"
                }
            if ($ContinueOnError -eq $false){
                $ContinueCommand = ""
            }

            #Set the value for the Config file if one exists.
            if (test-path "$Destination\Config.xml") {
                $LoadStateConfigFile = """$Destination\Config.xml"""
                $LoadStateConfig = "/i:$LoadStateConfigFile"
            }


        # Generate arguments for load state process
        $Logs = "`"/l:$Destination\load.log`" `"/progress:$Destination\load_progress.log`""

        # Set parameter for whether save state is compressed
        if ($UncompressedSource -eq $true) {
            $Uncompressed = '/nocompress'
        } else {
            $Uncompressed = ''
        }
        
        # Options for creating local accounts that don't already exist on new computer
        $LocalAccountOptions = ''
        if ($Script:DefaultLACreate -eq $true) {
            $LocalAccountOptions = "`"/lac:$Script:DefaultLAPassword`""
            if ($Script:DefaultLACEnable -eq $true) {
                $LocalAccountOptions += ' /lae'
            }
        } else {
            ''
        }

        # Check if user to be migrated is coming from a different domain and do a cross-domain migration if so
        if ($CrossDomainMigrationGroupBox.Enabled) {
            $OldUser = "$($OldDomainTextBox.Text)\$($OldUserNameTextBox.Text)"
            $NewUser = "$($NewDomainTextBox.Text)\$($NewUserNameTextBox.Text)"

            # Make sure the user entered a new user's user name before continuing
            if ($NewUserNameTextBox.Text -eq '') {
                Update-Log "New user's user name must not be empty." -Color 'Red'
                return
            }

            Update-Log "$OldUser will be migrated as $NewUser."
            $Arguments = "`"$Destination`" $LoadStateConfig $LocalAccountOptions `"/mu:$($OldUser):$NewUser`" $DecryptionSnytax $Uncompressed $Logs $ContinueCommand"
        } else {
            $Arguments = "`"$Destination`" $LoadStateConfig $LocalAccountOptions $DecryptionSnytax $Uncompressed $Logs $ContinueCommand"
        }

        # Begin loading user state to this computer
        Update-Log "Command used:"
        Update-Log "$LoadState $Arguments" -Color 'Cyan'

        # If we're running in debug mode don't actually start the process
        if ($Debug) { return }

        Update-Log "Loading state of $OldComputer..." -NoNewLine
        $USMTLoadState = Start-Process -FilePath $LoadState -ArgumentList $Arguments -Verb RunAs -PassThru
        $USMTLoadState
        # Give the process time to start before checking for its existence
        Start-Sleep -Seconds 3

        # Wait until the load state is complete
        try {
            $LoadProcess = Get-Process -Name loadstate -ErrorAction Stop
            while (-not $LoadProcess.HasExited) {
                Get-USMTProgress
                Start-Sleep -Seconds 1
            }

            Update-Log 'Results:'
            Get-USMTResults -ActionType 'load'

            # Sometimes loadstate will kill the explorer task and it needs to be start again manually
            if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
                Update-Log 'Restarting Explorer process.'
                Start-Process explorer
            }

            if ($USMTLoadState.ExitCode -eq 0){
            Update-Log "Complete!" -Color 'Green'
            # Delete the save state data
          
                try {
                    Get-ChildItem $MigrationStorePath | Remove-Item -Recurse
                    Update-Log 'Successfully removed old save state data.'
                } catch {
                    Update-Log 'There was an issue when trying to remove old save state data.'
                }
            } ELSE {
                update-log 'There was an issue during the loadstate process, please review the results. The state data was not deleted.'
            }
            } catch {
                Update-Log $_.Exception.Message -Color 'Red'
                    }
    }

    function Test-ComputerConnection {
        param(
            [System.Windows.Forms.TextBox] $ComputerNameTextBox,

            [System.Windows.Forms.TextBox] $ComputerIPTextBox,

            [System.Windows.Forms.CheckBox] $ConnectionCheckBox
        )

        $ConnectionCheckBox.Checked = $false

        # Try and use the IP if the user filled that out, otherwise use the name
        if ($ComputerIPTextBox.Text -ne '') {
            $Computer = $ComputerIPTextBox.Text
            # Try to update the computer's name with its IP address
            if ($ComputerNameTextBox.Text -eq '') {
                try {
                    Update-Log 'Computer name is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
                    $HostName = ([System.Net.Dns]::GetHostEntry($Computer)).HostName
                    $ComputerNameTextBox.Text = $HostName
                    Update-Log "Computer name set to $HostName."
                } catch {
                    Update-Log "Unable to resolve host name from IP address, you'll need to manually set this." -Color 'Red'
                    return
                }
            }
        } elseif ($ComputerNameTextBox.Text -ne '') {
            $Computer = $ComputerNameTextBox.Text
            # Try to update the computer's IP address using its DNS name
            try {
                Update-Log 'Computer IP address is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
                # Get the first IP address found, which is usually the primary adapter
                $IPAddress = ([System.Net.Dns]::GetHostEntry($Computer)).AddressList.IPAddressToString.Split('.', 1)[0]

                # Set IP address in text box
                $ComputerIPTextBox.Text = $IPAddress
                Update-Log "Computer IP address set to $IPAddress."
            } catch {
                Update-Log "Unable to resolve IP address from host name, you'll need to manually set this." -Color 'Red'
                return
            }
        } else {
            $Computer = $null
        }

        # Don't even try if both fields are empty
        if ($Computer) {
            # If the computer doesn't appear to have a valid office IP, such as if it's on VPN, don't allow the user to continue
            if ($ComputerIPTextBox.Text -notlike $ValidIPAddress) {
                Update-Log "$IPAddress does not appear to be a valid IP address. The Migration Tool requires an IP address matching $ValidIPAddress." -Color 'Red'
                return
            }

            Update-Log "Testing connection to $Computer..." -NoNewLine

            if (Test-Connection $Computer -Quiet) {
                $ConnectionCheckBox.Checked = $true
                Update-Log "Connection established." -Color 'Green'
            } else {
                Update-Log "Unable to reach $Computer." -Color 'Red'
                if ($ComputerIPTextBox.Text -eq '') {
                    Update-Log "Try entering $Computer's IP address." -Color 'Yellow'
                }
            }
        } else {
            Update-Log "Enter the computer's name or IP address."  -Color 'Red'
        }
    }

    function Set-Logo {
        Update-Log "             __  __ _                 _   _             " -Color 'LightBlue'
        Update-Log "            |  \/  (_) __ _ _ __ __ _| |_(_) ___  _ __  " -Color 'LightBlue'
        Update-Log "            | |\/| | |/ _`` | '__/ _`` | __| |/ _ \| '_ \ " -Color 'LightBlue'
        Update-Log "            | |  | | | (_| | | | (_| | |_| | (_) | | | |" -Color 'LightBlue'
        Update-Log "            |_|  |_|_|\__, |_|  \__,_|\__|_|\___/|_| |_|" -Color 'LightBlue'
        Update-Log "                _     |___/  _     _              _     " -Color 'LightBlue'
        Update-Log "               / \   ___ ___(_)___| |_ __ _ _ __ | |_   " -Color 'LightBlue'
        Update-Log "              / _ \ / __/ __| / __| __/ _`` | '_ \| __|  " -Color 'LightBlue'
        Update-Log "             / ___ \\__ \__ \ \__ \ || (_| | | | | |_   " -Color 'LightBlue'
        Update-Log "            /_/   \_\___/___/_|___/\__\__,_|_| |_|\__| $ScriptVersion" -Color 'LightBlue'
        Update-Log
        Update-Log '                        by Nick Rodriguez' -Color 'Gold'
        Update-Log
    }

    function Test-IsISE { if ($psISE) { $true } else { $false } }

    function Test-PSVersion {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Update-Log "You are running a version of PowerShell less than 3.0 - some features have been disabled."
            $ChangeSaveDestinationButton.Enabled = $false
            $ChangeSaveSourceButton.Enabled = $false
            $AddExtraDirectoryButton.Enabled = $false
        }
    }

    function Test-Email {
        $EmailSubject = "Migration Assistant Email Test"
        if ($SMTPConnectionCheckBox.Checked -or (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
            $SMTPConnectionCheckBox.Checked = $true

            $EmailRecipients = @()

            $EmailRecipientsDataGridView.Rows | ForEach-Object {
                $CurrentRowIndex = $_.Index
                $EmailRecipients += $EmailRecipientsDataGridView.Item(0, $CurrentRowIndex).Value
            }

            Update-Log "Sending test email to: $EmailRecipients"

            try {
                Send-MailMessage -From $EmailSenderTextBox.Text -To $EmailRecipients `
                    -Subject $EmailSubject -Body $LogTextBox.Text -SmtpServer $SMTPServerTextBox.Text `
                    -ErrorAction Stop
            } catch {
                Update-Log "Error occurred sending email: $($_.Exception.Message)" -Color 'Red'
            }
        } else {
            Update-Log "Unable to send email of results because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
        }
    }

    # Hide parent PowerShell window unless run from ISE
    if (-not $(Test-IsISE)) {
        $ShowWindowAsync = Add-Type -MemberDefinition @"
    [DllImport("user32.dll")] 
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow); 
"@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru
        $ShowWindowAsync::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle, 0) | Out-Null
    }

    # Load assemblies for building forms
    [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

    $Script:Destination = ''
}

process {
    # Create form
    $Form = New-Object System.Windows.Forms.Form 
    $Form.Text = 'Migration Assistant by Nick Rodriguez'
    $Form.Size = New-Object System.Drawing.Size(1000, 550) 
    $Form.SizeGripStyle = 'Hide'
    $Form.FormBorderStyle = 'FixedToolWindow'
    $Form.MaximizeBox = $false
    $Form.StartPosition = "CenterScreen"

    # Create tab controls
    $TabControl = New-object System.Windows.Forms.TabControl
    $TabControl.DataBindings.DefaultDataSourceUpdateMode = 0
    $TabControl.Location = New-Object System.Drawing.Size(10, 10)
    $TabControl.Size = New-Object System.Drawing.Size(480, 490)
    $Form.Controls.Add($TabControl)

    # Log output text box
    $LogTextBox = New-Object System.Windows.Forms.RichTextBox
    $LogTextBox.Location = New-Object System.Drawing.Size(500, 30) 
    $LogTextBox.Size = New-Object System.Drawing.Size(475, 472)
    $LogTextBox.ReadOnly = 'True'
    $LogTextBox.BackColor = 'Black'
    $LogTextBox.ForeColor = 'White'
    $LogTextBox.Font = 'Consolas, 10'
    $LogTextBox.DetectUrls = $false
    Set-Logo
    $Form.Controls.Add($LogTextBox)

    # Clear log button
    $ClearLogButton = New-Object System.Windows.Forms.Button
    $ClearLogButton.Location = New-Object System.Drawing.Size(370, 505)
    $ClearLogButton.Size = New-Object System.Drawing.Size(80, 20)
    $ClearLogButton.FlatStyle = 1
    $ClearLogButton.BackColor = 'White'
    $ClearLogButton.ForeColor = 'Black'
    $ClearLogButton.Text = 'Clear'
    $ClearLogButton.Add_Click({ $LogTextBox.Clear() })
    $LogTextBox.Controls.Add($ClearLogButton)

    # Create old computer tab
    $OldComputerTabPage = New-Object System.Windows.Forms.TabPage
    $OldComputerTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $OldComputerTabPage.UseVisualStyleBackColor = $true
    $OldComputerTabPage.Text = 'Old Computer'
    $TabControl.Controls.Add($OldComputerTabPage)

    # Computer info group
    $OldComputerInfoGroupBox = New-Object System.Windows.Forms.GroupBox
    $OldComputerInfoGroupBox.Location = New-Object System.Drawing.Size(10, 10)
    $OldComputerInfoGroupBox.Size = New-Object System.Drawing.Size(450, 87)
    $OldComputerInfoGroupBox.Text = 'Computer Info'
    $OldComputerTabPage.Controls.Add($OldComputerInfoGroupBox)

    # Name label
    $ComputerNameLabel_OldPage = New-Object System.Windows.Forms.Label
    $ComputerNameLabel_OldPage.Location = New-Object System.Drawing.Size(100, 12)
    $ComputerNameLabel_OldPage.Size = New-Object System.Drawing.Size(100, 22)
    $ComputerNameLabel_OldPage.Text = 'Computer Name'
    $OldComputerInfoGroupBox.Controls.Add($ComputerNameLabel_OldPage)

    # IP label
    $ComputerIPLabel_OldPage = New-Object System.Windows.Forms.Label
    $ComputerIPLabel_OldPage.Location = New-Object System.Drawing.Size(230, 12)
    $ComputerIPLabel_OldPage.Size = New-Object System.Drawing.Size(80, 22)
    $ComputerIPLabel_OldPage.Text = 'IP Address'
    $OldComputerInfoGroupBox.Controls.Add($ComputerIPLabel_OldPage)

    # Old Computer name label
    $OldComputerNameLabel_OldPage = New-Object System.Windows.Forms.Label
    $OldComputerNameLabel_OldPage.Location = New-Object System.Drawing.Size(12, 35)
    $OldComputerNameLabel_OldPage.Size = New-Object System.Drawing.Size(80, 22)
    $OldComputerNameLabel_OldPage.Text = 'Old Computer'
    $OldComputerInfoGroupBox.Controls.Add($OldComputerNameLabel_OldPage)

    # Old Computer name text box
    $OldComputerNameTextBox_OldPage = New-Object System.Windows.Forms.TextBox
    $OldComputerNameTextBox_OldPage.ReadOnly = $true
    $OldComputerNameTextBox_OldPage.Location = New-Object System.Drawing.Size(100, 34) 
    $OldComputerNameTextBox_OldPage.Size = New-Object System.Drawing.Size(120, 20)
    $OldComputerNameTextBox_OldPage.Text = Get-HostName
    $OldComputerInfoGroupBox.Controls.Add($OldComputerNameTextBox_OldPage)

    # Old Computer IP text box
    $OldComputerIPTextBox_OldPage = New-Object System.Windows.Forms.TextBox
    $OldComputerIPTextBox_OldPage.ReadOnly = $true
    $OldComputerIPTextBox_OldPage.Location = New-Object System.Drawing.Size(230, 34) 
    $OldComputerIPTextBox_OldPage.Size = New-Object System.Drawing.Size(90, 20)
    $OldComputerIPTextBox_OldPage.Text = Get-IPAddress
    $OldComputerInfoGroupBox.Controls.Add($OldComputerIPTextBox_OldPage)

    # New Computer name label
    $NewComputerNameLabel_OldPage = New-Object System.Windows.Forms.Label
    $NewComputerNameLabel_OldPage.Location = New-Object System.Drawing.Size(12, 57)
    $NewComputerNameLabel_OldPage.Size = New-Object System.Drawing.Size(80, 22)
    $NewComputerNameLabel_OldPage.Text = 'New Computer'
    $OldComputerInfoGroupBox.Controls.Add($NewComputerNameLabel_OldPage)

    # New Computer name text box
    $NewComputerNameTextBox_OldPage = New-Object System.Windows.Forms.TextBox 
    $NewComputerNameTextBox_OldPage.Location = New-Object System.Drawing.Size(100, 56) 
    $NewComputerNameTextBox_OldPage.Size = New-Object System.Drawing.Size(120, 20)
    $NewComputerNameTextBox_OldPage.Add_TextChanged({
        if ($ConnectionCheckBox_OldPage.Checked) {
            Update-Log 'Computer name changed, connection status unverified.' -Color 'Yellow'
            $ConnectionCheckBox_OldPage.Checked = $false
        }
    })
    $OldComputerInfoGroupBox.Controls.Add($NewComputerNameTextBox_OldPage)

    # New Computer IP text box
    $NewComputerIPTextBox_OldPage = New-Object System.Windows.Forms.TextBox 
    $NewComputerIPTextBox_OldPage.Location = New-Object System.Drawing.Size(230, 56) 
    $NewComputerIPTextBox_OldPage.Size = New-Object System.Drawing.Size(90, 20)
    $NewComputerIPTextBox_OldPage.Add_TextChanged({
        if ($ConnectionCheckBox_OldPage.Checked) {
            Update-Log 'Computer IP address changed, connection status unverified.' -Color 'Yellow'
            $ConnectionCheckBox_OldPage.Checked = $false
        }
    })
    $OldComputerInfoGroupBox.Controls.Add($NewComputerIPTextBox_OldPage)

    # Button to test connection to new computer
    $TestConnectionButton_OldPage = New-Object System.Windows.Forms.Button
    $TestConnectionButton_OldPage.Location = New-Object System.Drawing.Size(335, 33)
    $TestConnectionButton_OldPage.Size = New-Object System.Drawing.Size(100, 22)
    $TestConnectionButton_OldPage.Text = 'Test Connection'
    $TestConnectionButton_OldPage.Add_Click({
        Test-ComputerConnection -ComputerNameTextBox $NewComputerNameTextBox_OldPage `
        -ComputerIPTextBox $NewComputerIPTextBox_OldPage -ConnectionCheckBox $ConnectionCheckBox_OldPage
    })
    $OldComputerInfoGroupBox.Controls.Add($TestConnectionButton_OldPage)

    # Connected check box
    $ConnectionCheckBox_OldPage = New-Object System.Windows.Forms.CheckBox
    $ConnectionCheckBox_OldPage.Enabled = $false
    $ConnectionCheckBox_OldPage.Text = 'Connected'
    $ConnectionCheckBox_OldPage.Location = New-Object System.Drawing.Size(336, 58) 
    $ConnectionCheckBox_OldPage.Size = New-Object System.Drawing.Size(100, 20)
    $OldComputerInfoGroupBox.Controls.Add($ConnectionCheckBox_OldPage)

    # Profile selection group box
    $SelectProfileGroupBox = New-Object System.Windows.Forms.GroupBox
    $SelectProfileGroupBox.Location = New-Object System.Drawing.Size(240, 220)
    $SelectProfileGroupBox.Size = New-Object System.Drawing.Size(220, 100)
    $SelectProfileGroupBox.Text = 'Save State Destination'
    $OldComputerTabPage.Controls.Add($SelectProfileGroupBox)

    # Select profile(s) button
    $SelectProfileButton = New-Object System.Windows.Forms.Button
    $SelectProfileButton.Location = New-Object System.Drawing.Size(30, 20)
    $SelectProfileButton.Size = New-Object System.Drawing.Size(160, 20)
    $SelectProfileButton.Text = 'Select Profile(s) to Migrate'
    $SelectProfileButton.Add_Click({
        Update-Log "Please wait while profiles are found..."
        $Script:SelectedProfile = Get-UserProfiles | 
            Out-GridView -Title 'Profile Selection' -OutputMode Multiple
        Update-Log "Profile(s) selected for migration:"
        $Script:SelectedProfile | ForEach-Object { Update-Log $_.UserName }
    })
    $SelectProfileGroupBox.Controls.Add($SelectProfileButton)

    # Recent profile day limit text box
    $RecentProfilesDaysTextBox = New-Object System.Windows.Forms.TextBox 
    $RecentProfilesDaysTextBox.Location = New-Object System.Drawing.Size(165, 70) 
    $RecentProfilesDaysTextBox.Size = New-Object System.Drawing.Size(40, 20)
    $RecentProfilesDaysTextBox.Text = 90
    $SelectProfileGroupBox.Controls.Add($RecentProfilesDaysTextBox)

    # Only recent profiles check box
    $RecentProfilesCheckBox = New-Object System.Windows.Forms.CheckBox
    $RecentProfilesCheckBox.Text = 'Migrate all profiles logged into within this amount of days:'
    $RecentProfilesCheckBox.Location = New-Object System.Drawing.Size(15, 50) 
    $RecentProfilesCheckBox.Size = New-Object System.Drawing.Size(200, 40)
    $RecentProfilesCheckBox.Add_Click({
        if ($RecentProfilesCheckBox.Checked -eq $true) {
            Update-Log "All profiles logged into within the last $($RecentProfilesDaysTextBox.Text) days will be saved."
            $SelectProfileButton.Enabled = $false
        } else {
            Update-Log "Recent profile save disabled." -Color Yellow
            $SelectProfileButton.Enabled = $true
        }
    })
    $SelectProfileGroupBox.Controls.Add($RecentProfilesCheckBox)

    # Alternative save location group box
    $SaveDestinationGroupBox = New-Object System.Windows.Forms.GroupBox
    $SaveDestinationGroupBox.Location = New-Object System.Drawing.Size(240, 110)
    $SaveDestinationGroupBox.Size = New-Object System.Drawing.Size(220, 100)
    $SaveDestinationGroupBox.Text = 'Save State Destination'
    $OldComputerTabPage.Controls.Add($SaveDestinationGroupBox)

    # Save path
    $SaveDestinationTextBox = New-Object System.Windows.Forms.TextBox
    $SaveDestinationTextBox.Text = $MigrationStorePath
    $SaveDestinationTextBox.Location = New-Object System.Drawing.Size(5, 20) 
    $SaveDestinationTextBox.Size = New-Object System.Drawing.Size(210, 20)
    $SaveDestinationGroupBox.Controls.Add($SaveDestinationTextBox)

    # Alternative save check box
    $SaveRemotelyCheckBox = New-Object System.Windows.Forms.CheckBox
    $SaveRemotelyCheckBox.Text = 'Save on new computer'
    $SaveRemotelyCheckBox.Checked = $true
    $SaveRemotelyCheckBox.Location = New-Object System.Drawing.Size(45, 45)
    $SaveRemotelyCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    $SaveRemotelyCheckBox.Add_Click({
        if ($SaveRemotelyCheckBox.Checked -eq $true) {
            $OldComputerInfoGroupBox.Enabled = $true
            Update-Log 'Local save destination disabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Save state will be stored on the new computer and network checks will be processed normally.'
        } else {
            $OldComputerInfoGroupBox.Enabled = $false
            Update-Log 'Local save destination enabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Save state will be stored locally and network checks will be skipped.'
        }
    })
    $SaveDestinationGroupBox.Controls.Add($SaveRemotelyCheckBox)

    # Change save destination button
    $ChangeSaveDestinationButton = New-Object System.Windows.Forms.Button
    $ChangeSaveDestinationButton.Location = New-Object System.Drawing.Size(35, 70)
    $ChangeSaveDestinationButton.Size = New-Object System.Drawing.Size(60, 20)
    $ChangeSaveDestinationButton.Text = 'Change'
    $ChangeSaveDestinationButton.Add_Click({ Set-SaveDirectory -Type Destination })
    $SaveDestinationGroupBox.Controls.Add($ChangeSaveDestinationButton)

    # Reset save destination button
    $ResetSaveDestinationButton = New-Object System.Windows.Forms.Button
    $ResetSaveDestinationButton.Location = New-Object System.Drawing.Size(120, 70)
    $ResetSaveDestinationButton.Size = New-Object System.Drawing.Size(65, 20)
    $ResetSaveDestinationButton.Text = 'Reset'
    $ResetSaveDestinationButton.Add_Click({
        Update-Log "Resetting save directory to [$MigrationStorePath]."
        $SaveDestinationTextBox.Text = $MigrationStorePath
    })
    $SaveDestinationGroupBox.Controls.Add($ResetSaveDestinationButton)

    # Inclusions group box
    $InclusionsGroupBox = New-Object System.Windows.Forms.GroupBox
    $InclusionsGroupBox.Location = New-Object System.Drawing.Size(10, 110)
    $InclusionsGroupBox.Size = New-Object System.Drawing.Size(220, 140)
    $InclusionsGroupBox.Text = 'Data to Include'
    $OldComputerTabPage.Controls.Add($InclusionsGroupBox)

    # AppData check box CSIDL_APPDATA
    $IncludeAppDataCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeAppDataCheckBox.Checked = $DefaultIncludeAppData
    $IncludeAppDataCheckBox.Text = 'AppData'
    $IncludeAppDataCheckBox.Location = New-Object System.Drawing.Size(10, 15) 
    $IncludeAppDataCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeAppDataCheckBox.Add_Click({
        $ComponentName = $IncludeAppDataCheckBox.Text
        if ($IncludeAppDataCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included."
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeAppDataCheckBox)

    # Local AppData check box CSIDL_LOCAL_APPDATA
    $IncludeLocalAppDataCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeLocalAppDataCheckBox.Checked = $DefaultIncludeLocalAppData
    $IncludeLocalAppDataCheckBox.Text = 'Local AppData'
    $IncludeLocalAppDataCheckBox.Location = New-Object System.Drawing.Size(10, 35) 
    $IncludeLocalAppDataCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeLocalAppDataCheckBox.Add_Click({
        $ComponentName = $IncludeLocalAppDataCheckBox.Text
        if ($IncludeLocalAppDataCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeLocalAppDataCheckBox)
    
    # Printers check box CSIDL_PRINTERS
    $IncludePrintersCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludePrintersCheckBox.Checked = $DefaultIncludePrinters
    $IncludePrintersCheckBox.Text = 'Printers'
    $IncludePrintersCheckBox.Location = New-Object System.Drawing.Size(10, 55) 
    $IncludePrintersCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludePrintersCheckBox.Add_Click({
        $ComponentName = $IncludePrintersCheckBox.Text
        if ($IncludePrintersCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludePrintersCheckBox)
    
    # Recycle Bin check box CSIDL_BITBUCKET
    $IncludeRecycleBinCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeRecycleBinCheckBox.Checked = $DefaultIncludeRecycleBin
    $IncludeRecycleBinCheckBox.Text = 'Recycle Bin'
    $IncludeRecycleBinCheckBox.Location = New-Object System.Drawing.Size(10, 75) 
    $IncludeRecycleBinCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeRecycleBinCheckBox.Add_Click({
        $ComponentName = $IncludeRecycleBinCheckBox.Text
        if ($IncludeRecycleBinCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeRecycleBinCheckBox)

    # My Documents check box CSIDL_MYDOCUMENTS and CSIDL_PERSONAL
    $IncludeMyDocumentsCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyDocumentsCheckBox.Checked = $DefaultIncludeMyDocuments
    $IncludeMyDocumentsCheckBox.Text = 'My Documents'
    $IncludeMyDocumentsCheckBox.Location = New-Object System.Drawing.Size(10, 95) 
    $IncludeMyDocumentsCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyDocumentsCheckBox.Add_Click({
        $ComponentName = $IncludeMyDocumentsCheckBox.Text
        if ($IncludeMyDocumentsCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeMyDocumentsCheckBox)

    # Wallpapers
    $IncludeWallpapersCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeWallpapersCheckBox.Checked = $DefaultIncludeWallpapers
    $IncludeWallpapersCheckBox.Text = 'Wallpapers'
    $IncludeWallpapersCheckBox.Location = New-Object System.Drawing.Size(10, 115) 
    $IncludeWallpapersCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeWallpapersCheckBox.Add_Click({
        $ComponentName = $IncludeWallpapersCheckBox.Text
        if ($IncludeWallpapersCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeWallpapersCheckBox)
    
    # Desktop check box CSIDL_DESKTOP and CSIDL_DESKTOPDIRECTORY
    $IncludeDesktopCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeDesktopCheckBox.Checked = $DefaultIncludeDesktop
    $IncludeDesktopCheckBox.Text = 'Desktop'
    $IncludeDesktopCheckBox.Location = New-Object System.Drawing.Size(110, 15) 
    $IncludeDesktopCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeDesktopCheckBox.Add_Click({
        $ComponentName = $IncludeDesktopCheckBox.Text
        if ($IncludeDesktopCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeDesktopCheckBox)

    # Favorites check box CSIDL_FAVORITES
    $IncludeFavoritesCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeFavoritesCheckBox.Checked = $DefaultIncludeFavorites
    $IncludeFavoritesCheckBox.Text = 'Favorites'
    $IncludeFavoritesCheckBox.Location = New-Object System.Drawing.Size(110, 35) 
    $IncludeFavoritesCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeFavoritesCheckBox.Add_Click({
        $ComponentName = $IncludeFavoritesCheckBox.Text
        if ($IncludeFavoritesCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeFavoritesCheckBox)

    # My Music check box CSIDL_MYMUSIC
    $IncludeMyMusicCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyMusicCheckBox.Checked = $DefaultIncludeMyMusic
    $IncludeMyMusicCheckBox.Text = 'My Music'
    $IncludeMyMusicCheckBox.Location = New-Object System.Drawing.Size(110, 55) 
    $IncludeMyMusicCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyMusicCheckBox.Add_Click({
        $ComponentName = $IncludeMyMusicCheckBox.Text
        if ($IncludeMyMusicCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeMyMusicCheckBox)

    # My Pictures check box CSIDL_MYPICTURES
    $IncludeMyPicturesCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyPicturesCheckBox.Checked = $DefaultIncludeMyPictures
    $IncludeMyPicturesCheckBox.Text = 'My Pictures'
    $IncludeMyPicturesCheckBox.Location = New-Object System.Drawing.Size(110, 75) 
    $IncludeMyPicturesCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyPicturesCheckBox.Add_Click({
        $ComponentName = $IncludeMyPicturesCheckBox.Text
        if ($IncludeMyPicturesCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }

        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeMyPicturesCheckBox)

    # My Video check box CSIDL_MYVIDEO
    $IncludeMyVideoCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyVideoCheckBox.Checked = $DefaultIncludeMyVideo
    $IncludeMyVideoCheckBox.Text = 'My Video'
    $IncludeMyVideoCheckBox.Location = New-Object System.Drawing.Size(110, 95) 
    $IncludeMyVideoCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyVideoCheckBox.Add_Click({
        $ComponentName = $IncludeMyVideoCheckBox.Text
        if ($IncludeMyVideoCheckBox.Checked -eq $true) {
            Update-Log "$ComponentName will be included."
            if ($SelectedXMLS){
                Remove-variable -name SelectedXMLS -Scope Script -Force
                Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
           }
        } else {
            Update-Log "$ComponentName will not be included." -Color Yellow
        }
    })
    $InclusionsGroupBox.Controls.Add($IncludeMyVideoCheckBox)
    
    # Custom XML Box
    $IncludeCustomXMLButton = New-Object System.Windows.Forms.Button
   # $IncludeCustomXMLCheckBox.Checked = $DefaultIncludeMyVideo
    $IncludeCustomXMLButton.Text = 'Custom XML(s)'
    $IncludeCustomXMLButton.Location = New-Object System.Drawing.Size(110, 115) 
    $IncludeCustomXMLButton.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeCustomXMLButton.Add_Click({
        #Create an array object as well as clear any existing Custom XML list if present
        $Script:DiscoveredXMLS = @()
        $Script:SelectedXMLS = @()
        Update-Log "Please wait while Custom XML Files are found..."
        $Script:DiscoveredXMLS = get-childitem "$Script:USMTPath\*.xml"  -Exclude "MigLog.xml"
        #Create a Description property
        $Script:DiscoveredXMLS |Add-Member -NotePropertyName Description -NotePropertyValue "No Description Available"
        foreach ($XMLFile in $Script:DiscoveredXMLS){
            $XMLDescriptionFile = $XmlFIle -Replace ".xml",".txt"
            if (Test-path $XMLDescriptionFIle){
                $XMLDescription = get-content $XMLDescriptionFile
                $XmlFile.Description = $XMLDescription
                }
            }

        $Script:DiscoveredXMLS |
            Select -Property Name,Description |
                Out-GridView -Title 'Custom XML file selection' -OutputMode Multiple |foreach {$Script:SelectedXMLS += $_.Name}

        update-log "Xmls(s) selected for migration:"
        foreach ($XML in $Script:SelectedXMLS){
             update-log $XML}

    #Uncheck other Selections.

    $IncludeAppDataCheckBox.Checked = $False
    $IncludeLocalAppDataCheckBox.Checked = $False
    $IncludePrintersCheckBox.Checked = $False
    $IncludeRecycleBinCheckBox.Checked = $False
    $IncludeWallpapersCheckBox.Checked = $False
     $IncludeMyDocumentsCheckBox.Checked = $False
    $IncludeDesktopCheckBox.Checked = $False
    $IncludeFavoritesCheckBox.Checked = $False
    $IncludeMyMusicCheckBox.Checked = $False
    $IncludeMyPicturesCheckBox.Checked = $False
    $IncludeMyPicturesCheckBox.Checked = $False
    $IncludeMyVideoCheckBox.Checked = $False

    })
    $InclusionsGroupBox.Controls.Add($IncludeCustomXMLButton)

    # Extra directories selection group box
    $ExtraDirectoriesGroupBox = New-Object System.Windows.Forms.GroupBox
    $ExtraDirectoriesGroupBox.Location = New-Object System.Drawing.Size(10, 260)
    $ExtraDirectoriesGroupBox.Size = New-Object System.Drawing.Size(220, 200)
    $ExtraDirectoriesGroupBox.Text = 'Extra Directories to Include'
    $OldComputerTabPage.Controls.Add($ExtraDirectoriesGroupBox)
    
    # Extra directories data table
    $ExtraDirectoriesDataGridView = New-Object System.Windows.Forms.DataGridView
    $ExtraDirectoriesDataGridView.Location = New-Object System.Drawing.Size(5, 20)
    $ExtraDirectoriesDataGridView.Size = New-Object System.Drawing.Size(210, 170)
    $ExtraDirectoriesDataGridView.ReadOnly = $true
    $ExtraDirectoriesDataGridView.AllowUserToAddRows = $false
    $ExtraDirectoriesDataGridView.AllowUserToResizeRows = $false
    $ExtraDirectoriesDataGridView.AllowUserToResizeColumns = $false
    $ExtraDirectoriesDataGridView.MultiSelect = $false
    $ExtraDirectoriesDataGridView.ColumnCount = 1
    $ExtraDirectoriesDataGridView.AutoSizeColumnsMode = 'Fill'
    $ExtraDirectoriesDataGridView.ColumnHeadersVisible = $false
    $ExtraDirectoriesDataGridView.RowHeadersVisible = $false
    $ExtraDirectoriesGroupBox.Controls.Add($ExtraDirectoriesDataGridView)

    # Remove Extra directory button
    $RemoveExtraDirectoryButton = New-Object System.Windows.Forms.Button
    $RemoveExtraDirectoryButton.Location = New-Object System.Drawing.Size(0, 150)
    $RemoveExtraDirectoryButton.Size = New-Object System.Drawing.Size(20, 20)
    $RemoveExtraDirectoryButton.Text = '-'
    $RemoveExtraDirectoryButton.Font = 'Consolas, 14'
    $RemoveExtraDirectoryButton.Add_Click({ Remove-ExtraDirectory })
    $ExtraDirectoriesDataGridView.Controls.Add($RemoveExtraDirectoryButton)

    # Add Extra directory button
    $AddExtraDirectoryButton = New-Object System.Windows.Forms.Button
    $AddExtraDirectoryButton.Location = New-Object System.Drawing.Size(20, 150)
    $AddExtraDirectoryButton.Size = New-Object System.Drawing.Size(20, 20)
    $AddExtraDirectoryButton.Text = '+'
    $AddExtraDirectoryButton.Font = 'Consolas, 14'
    $AddExtraDirectoryButton.Add_Click({ Add-ExtraDirectory })
    $ExtraDirectoriesDataGridView.Controls.Add($AddExtraDirectoryButton)

    # Uncompressed storage check box
    $UncompressedCheckBox = New-Object System.Windows.Forms.CheckBox
    $UncompressedCheckBox.Text = 'Uncompressed storage'
    $UncompressedCheckBox.Location = New-Object System.Drawing.Size(280, 350) 
    $UncompressedCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $UncompressedCheckBox.Add_Click({
        if ($UncompressedCheckBox.Checked -eq $true) {
            Update-Log 'Uncompressed save state enabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Save state will be stored as uncompressed flat files.'
        } else {
            Update-Log 'Uncompressed save state disabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Save state will be stored as a compressed file.'
        }
    })
    $OldComputerTabPage.Controls.Add($UncompressedCheckBox)

    # Migrate button
    $MigrateButton_OldPage = New-Object System.Windows.Forms.Button
    $MigrateButton_OldPage.Location = New-Object System.Drawing.Size(300, 400)
    $MigrateButton_OldPage.Size = New-Object System.Drawing.Size(100, 40)
    $MigrateButton_OldPage.Font = New-Object System.Drawing.Font('Calibri', 16, [System.Drawing.FontStyle]::Bold)
    $MigrateButton_OldPage.Text = 'Migrate'
    $MigrateButton_OldPage.Add_Click({ Save-UserState })
    $OldComputerTabPage.Controls.Add($MigrateButton_OldPage)

    # Create new computer tab
    $NewComputerTabPage = New-Object System.Windows.Forms.TabPage
    $NewComputerTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $NewComputerTabPage.UseVisualStyleBackColor = $true
    $NewComputerTabPage.Text = 'New Computer'
    $TabControl.Controls.Add($NewComputerTabPage)

    # Computer info group
    $NewComputerInfoGroupBox = New-Object System.Windows.Forms.GroupBox
    $NewComputerInfoGroupBox.Location = New-Object System.Drawing.Size(10, 10)
    $NewComputerInfoGroupBox.Size = New-Object System.Drawing.Size(450, 87)
    $NewComputerInfoGroupBox.Text = 'Computer Info'
    $NewComputerTabPage.Controls.Add($NewComputerInfoGroupBox)
    
    # Alternative save location group box
    $SaveSourceGroupBox = New-Object System.Windows.Forms.GroupBox
    $SaveSourceGroupBox.Location = New-Object System.Drawing.Size(240, 110)
    $SaveSourceGroupBox.Size = New-Object System.Drawing.Size(220, 87)
    $SaveSourceGroupBox.Text = 'Save State Source'
    $NewComputerTabPage.Controls.Add($SaveSourceGroupBox)

    # Save path
    $SaveSourceTextBox = New-Object System.Windows.Forms.TextBox
    $SaveSourceTextBox.Text = $MigrationStorePath
    $SaveSourceTextBox.Location = New-Object System.Drawing.Size(5, 20) 
    $SaveSourceTextBox.Size = New-Object System.Drawing.Size(210, 20)
    $SaveSourceGroupBox.Controls.Add($SaveSourceTextBox)

    # Change save destination button
    $ChangeSaveSourceButton = New-Object System.Windows.Forms.Button
    $ChangeSaveSourceButton.Location = New-Object System.Drawing.Size(5, 50)
    $ChangeSaveSourceButton.Size = New-Object System.Drawing.Size(60, 20)
    $ChangeSaveSourceButton.Text = 'Change'
    $ChangeSaveSourceButton.Add_Click({ 
        Set-SaveDirectory -Type Source
        $OldComputerNameTextBox_NewPage.Text = Get-SaveState
        Show-DomainInfo
    })
    $SaveSourceGroupBox.Controls.Add($ChangeSaveSourceButton)

    # Reset save destination button
    $ResetSaveSourceButton = New-Object System.Windows.Forms.Button
    $ResetSaveSourceButton.Location = New-Object System.Drawing.Size(75, 50)
    $ResetSaveSourceButton.Size = New-Object System.Drawing.Size(65, 20)
    $ResetSaveSourceButton.Text = 'Reset'
    $ResetSaveSourceButton.Add_Click({
        Update-Log "Resetting save state directory to [$MigrationStorePath]."
        $SaveSourceTextBox.Text = $MigrationStorePath
        $OldComputerNameTextBox_NewPage.Text = Get-SaveState
        Show-DomainInfo
    })
    $SaveSourceGroupBox.Controls.Add($ResetSaveSourceButton)

    # Search for save state in given SaveSourceTextBox path
    $ResetSaveSourceButton = New-Object System.Windows.Forms.Button
    $ResetSaveSourceButton.Location = New-Object System.Drawing.Size(150, 50)
    $ResetSaveSourceButton.Size = New-Object System.Drawing.Size(65, 20)
    $ResetSaveSourceButton.Text = 'Search'
    $ResetSaveSourceButton.Add_Click({
        $OldComputerNameTextBox_NewPage.Text = Get-SaveState
        Show-DomainInfo
    })
    $SaveSourceGroupBox.Controls.Add($ResetSaveSourceButton)
    
    # Name label
    $ComputerNameLabel_NewPage = New-Object System.Windows.Forms.Label
    $ComputerNameLabel_NewPage.Location = New-Object System.Drawing.Size(100, 12)
    $ComputerNameLabel_NewPage.Size = New-Object System.Drawing.Size(100, 22)
    $ComputerNameLabel_NewPage.Text = 'Computer Name'
    $NewComputerInfoGroupBox.Controls.Add($ComputerNameLabel_NewPage)

    # IP label
    $ComputerIPLabel_NewPage = New-Object System.Windows.Forms.Label
    $ComputerIPLabel_NewPage.Location = New-Object System.Drawing.Size(230, 12)
    $ComputerIPLabel_NewPage.Size = New-Object System.Drawing.Size(80, 22)
    $ComputerIPLabel_NewPage.Text = 'IP Address'
    $NewComputerInfoGroupBox.Controls.Add($ComputerIPLabel_NewPage)

    # Old Computer name label
    $OldComputerNameLabel_NewPage = New-Object System.Windows.Forms.Label
    $OldComputerNameLabel_NewPage.Location = New-Object System.Drawing.Size(12, 35)
    $OldComputerNameLabel_NewPage.Size = New-Object System.Drawing.Size(80, 22)
    $OldComputerNameLabel_NewPage.Text = 'Old Computer'
    $NewComputerInfoGroupBox.Controls.Add($OldComputerNameLabel_NewPage)

    # Old Computer name text box
    $OldComputerNameTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $OldComputerNameTextBox_NewPage.ReadOnly = $true
    $OldComputerNameTextBox_NewPage.Location = New-Object System.Drawing.Size(100, 34) 
    $OldComputerNameTextBox_NewPage.Size = New-Object System.Drawing.Size(120, 20)
    $OldComputerNameTextBox_NewPage.Text = Get-SaveState
    $NewComputerInfoGroupBox.Controls.Add($OldComputerNameTextBox_NewPage)

    # Old Computer IP text box
    $OldComputerIPTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $OldComputerIPTextBox_NewPage.Location = New-Object System.Drawing.Size(230, 34) 
    $OldComputerIPTextBox_NewPage.Size = New-Object System.Drawing.Size(90, 20)
    $OldComputerIPTextBox_NewPage.Add_TextChanged({
        if ($ConnectionCheckBox_NewPage.Checked) {
            Update-Log 'Computer IP address changed, connection status unverified.' -Color 'Yellow'
            $ConnectionCheckBox_NewPage.Checked = $false
        }
    })
    $NewComputerInfoGroupBox.Controls.Add($OldComputerIPTextBox_NewPage)

    # New Computer name label
    $NewComputerNameLabel_NewPage = New-Object System.Windows.Forms.Label
    $NewComputerNameLabel_NewPage.Location = New-Object System.Drawing.Size(12, 57)
    $NewComputerNameLabel_NewPage.Size = New-Object System.Drawing.Size(80, 22)
    $NewComputerNameLabel_NewPage.Text = 'New Computer'
    $NewComputerInfoGroupBox.Controls.Add($NewComputerNameLabel_NewPage)

    # New Computer name text box
    $NewComputerNameTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $NewComputerNameTextBox_NewPage.ReadOnly = $true
    $NewComputerNameTextBox_NewPage.Location = New-Object System.Drawing.Size(100, 56)
    $NewComputerNameTextBox_NewPage.Size = New-Object System.Drawing.Size(120, 20)
    $NewComputerNameTextBox_NewPage.Text = Get-HostName
    $NewComputerInfoGroupBox.Controls.Add($NewComputerNameTextBox_NewPage)

    # New Computer IP text box
    $NewComputerIPTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $NewComputerIPTextBox_NewPage.ReadOnly = $true
    $NewComputerIPTextBox_NewPage.Location = New-Object System.Drawing.Size(230, 56)
    $NewComputerIPTextBox_NewPage.Size = New-Object System.Drawing.Size(90, 20)
    $NewComputerIPTextBox_NewPage.Text = Get-IPAddress
    $NewComputerInfoGroupBox.Controls.Add($NewComputerIPTextBox_NewPage)

    # Button to test connection to new computer
    $TestConnectionButton_NewPage = New-Object System.Windows.Forms.Button
    $TestConnectionButton_NewPage.Location = New-Object System.Drawing.Size(335, 33)
    $TestConnectionButton_NewPage.Size = New-Object System.Drawing.Size(100, 22)
    $TestConnectionButton_NewPage.Text = 'Test Connection'
    $TestConnectionButton_NewPage.Add_Click({
        Test-ComputerConnection -ComputerNameTextBox $OldComputerNameTextBox_NewPage `
        -ComputerIPTextBox $OldComputerIPTextBox_NewPage -ConnectionCheckBox $ConnectionCheckBox_NewPage          
    })
    $NewComputerInfoGroupBox.Controls.Add($TestConnectionButton_NewPage)

    # Connected check box
    $ConnectionCheckBox_NewPage = New-Object System.Windows.Forms.CheckBox
    $ConnectionCheckBox_NewPage.Enabled = $false
    $ConnectionCheckBox_NewPage.Text = 'Connected'
    $ConnectionCheckBox_NewPage.Location = New-Object System.Drawing.Size(336, 58) 
    $ConnectionCheckBox_NewPage.Size = New-Object System.Drawing.Size(100, 20)
    $NewComputerInfoGroupBox.Controls.Add($ConnectionCheckBox_NewPage)

    # Cross-domain migration group box
    $CrossDomainMigrationGroupBox = New-Object System.Windows.Forms.GroupBox
    $CrossDomainMigrationGroupBox.Location = New-Object System.Drawing.Size(10, 110)
    $CrossDomainMigrationGroupBox.Size = New-Object System.Drawing.Size(220, 87)
    $CrossDomainMigrationGroupBox.Text = 'Cross-Domain Migration'
    $NewComputerTabPage.Controls.Add($CrossDomainMigrationGroupBox)

    # Domain label
    $DomainLabel = New-Object System.Windows.Forms.Label
    $DomainLabel.Location = New-Object System.Drawing.Size(70, 12)
    $DomainLabel.Size = New-Object System.Drawing.Size(50, 22)
    $DomainLabel.Text = 'Domain'
    $CrossDomainMigrationGroupBox.Controls.Add($DomainLabel)

    # User name label
    $UserNameLabel = New-Object System.Windows.Forms.Label
    $UserNameLabel.Location = New-Object System.Drawing.Size(125, 12)
    $UserNameLabel.Size = New-Object System.Drawing.Size(80, 22)
    $UserNameLabel.Text = 'User Name'
    $CrossDomainMigrationGroupBox.Controls.Add($UserNameLabel)

    # Old user label
    $OldUserLabel = New-Object System.Windows.Forms.Label
    $OldUserLabel.Location = New-Object System.Drawing.Size(12, 35)
    $OldUserLabel.Size = New-Object System.Drawing.Size(50, 22)
    $OldUserLabel.Text = 'Old User'
    $CrossDomainMigrationGroupBox.Controls.Add($OldUserLabel)

    # Old domain text box
    $OldDomainTextBox = New-Object System.Windows.Forms.TextBox
    $OldDomainTextBox.ReadOnly = $true
    $OldDomainTextBox.Location = New-Object System.Drawing.Size(70, 34) 
    $OldDomainTextBox.Size = New-Object System.Drawing.Size(40, 20)
    $OldDomainTextBox.Text = $OldComputerNameTextBox_NewPage.Text
    $CrossDomainMigrationGroupBox.Controls.Add($OldDomainTextBox)

    # Old user slash label
    $OldUserSlashLabel = New-Object System.Windows.Forms.Label
    $OldUserSlashLabel.Location = New-Object System.Drawing.Size(110, 33)
    $OldUserSlashLabel.Size = New-Object System.Drawing.Size(10, 20)
    $OldUserSlashLabel.Text = '\'
    $OldUserSlashLabel.Font = New-Object System.Drawing.Font('Calibri', 12)
    $CrossDomainMigrationGroupBox.Controls.Add($OldUserSlashLabel)

    # Old user name text box
    $OldUserNameTextBox = New-Object System.Windows.Forms.TextBox
    $OldUserNameTextBox.ReadOnly = $true
    $OldUserNameTextBox.Location = New-Object System.Drawing.Size(125, 34) 
    $OldUserNameTextBox.Size = New-Object System.Drawing.Size(80, 20)
    $CrossDomainMigrationGroupBox.Controls.Add($OldUserNameTextBox)

    # New user label
    $NewUserLabel = New-Object System.Windows.Forms.Label
    $NewUserLabel.Location = New-Object System.Drawing.Size(12, 57)
    $NewUserLabel.Size = New-Object System.Drawing.Size(55, 22)
    $NewUserLabel.Text = 'New User'
    $CrossDomainMigrationGroupBox.Controls.Add($NewUserLabel)

    # New domain text box
    $NewDomainTextBox = New-Object System.Windows.Forms.TextBox
    $NewDomainTextBox.ReadOnly = $true
    $NewDomainTextBox.Location = New-Object System.Drawing.Size(70, 56)
    $NewDomainTextBox.Size = New-Object System.Drawing.Size(40, 20)
    $NewDomainTextBox.Text = $DefaultDomain
    $CrossDomainMigrationGroupBox.Controls.Add($NewDomainTextBox)

    # New user slash label
    $NewUserSlashLabel = New-Object System.Windows.Forms.Label
    $NewUserSlashLabel.Location = New-Object System.Drawing.Size(110, 56)
    $NewUserSlashLabel.Size = New-Object System.Drawing.Size(10, 20)
    $NewUserSlashLabel.Text = '\'
    $NewUserSlashLabel.Font = New-Object System.Drawing.Font('Calibri', 12)
    $CrossDomainMigrationGroupBox.Controls.Add($NewUserSlashLabel)

    # New user name text box
    $NewUserNameTextBox = New-Object System.Windows.Forms.TextBox
    $NewUserNameTextBox.Location = New-Object System.Drawing.Size(125, 56)
    $NewUserNameTextBox.Size = New-Object System.Drawing.Size(80, 20)
	$NewUserNameTextBox.Text = $env:USERNAME
    $CrossDomainMigrationGroupBox.Controls.Add($NewUserNameTextBox)

    # Override check box
    $OverrideCheckBox = New-Object System.Windows.Forms.CheckBox
    $OverrideCheckBox.Text = 'Save state task completed'
    $OverrideCheckBox.Location = New-Object System.Drawing.Size(280, 225) 
    $OverrideCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $OverrideCheckBox.Add_Click({
        if ($OverrideCheckBox.Checked -eq $true) {
            $NewComputerInfoGroupBox.Enabled = $false
            Update-Log 'Network connection override enabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Save state process on old computer is assumed to be completed and no network checks will be processed during load state.'
        } else {
            $NewComputerInfoGroupBox.Enabled = $true
            Update-Log 'Network connection override enabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Network checks will be processed during load state.'
        }
    })
    $NewComputerTabPage.Controls.Add($OverrideCheckBox)

    Show-DomainInfo

    # Migrate button
    $MigrateButton_NewPage = New-Object System.Windows.Forms.Button
    $MigrateButton_NewPage.Location = New-Object System.Drawing.Size(300, 400)
    $MigrateButton_NewPage.Size = New-Object System.Drawing.Size(100, 40)
    $MigrateButton_NewPage.Font = New-Object System.Drawing.Font('Calibri', 16, [System.Drawing.FontStyle]::Bold)
    $MigrateButton_NewPage.Text = 'Migrate'
    $MigrateButton_NewPage.Add_Click({ Load-UserState })
    $NewComputerTabPage.Controls.Add($MigrateButton_NewPage)

    # Create email settings tab
    $EmailSettingsTabPage = New-Object System.Windows.Forms.TabPage
    $EmailSettingsTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $EmailSettingsTabPage.UseVisualStyleBackColor = $true
    $EmailSettingsTabPage.Text = 'Email Settings'
    $TabControl.Controls.Add($EmailSettingsTabPage)

    # Email enabled check box
    $EmailCheckBox = New-Object System.Windows.Forms.CheckBox
    $EmailCheckBox.Text = 'Enabled'
    $EmailCheckBox.Location = New-Object System.Drawing.Size(10, 10) 
    $EmailCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $EmailCheckBox.Checked = $DefaultEmailEnabled
    $EmailCheckBox.Add_Click({
        if ($EmailCheckBox.Checked -eq $true) {
            Update-Log 'Email enabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - Results will be emailed to supplied email addresses (if your account has email relay access).'
        } else {
            Update-Log 'Email disabled' -Color 'Yellow' -NoNewLine
            Update-Log ' - No results will be emailed.'
        }
    })
    $EmailSettingsTabPage.Controls.Add($EmailCheckBox)

    # SMTP server group box
    $SMTPServerGroupBox = New-Object System.Windows.Forms.GroupBox
    $SMTPServerGroupBox.Location = New-Object System.Drawing.Size(10, 60)
    $SMTPServerGroupBox.Size = New-Object System.Drawing.Size(220, 80)
    $SMTPServerGroupBox.Text = 'SMTP Server'
    $EmailSettingsTabPage.Controls.Add($SMTPServerGroupBox)

    # SMTP server text box
    $SMTPServerTextBox = New-Object System.Windows.Forms.TextBox
    $SMTPServerTextBox.Location = New-Object System.Drawing.Size(5, 20) 
    $SMTPServerTextBox.Size = New-Object System.Drawing.Size(210, 25)
    $SMTPServerTextBox.Text = $DefaultSMTPServer
    $SMTPServerGroupBox.Controls.Add($SMTPServerTextBox)

    # Button to test connection to SMTP server
    $SMTPConnectionButton = New-Object System.Windows.Forms.Button
    $SMTPConnectionButton.Location = New-Object System.Drawing.Size(9, 50)
    $SMTPConnectionButton.Size = New-Object System.Drawing.Size(100, 22)
    $SMTPConnectionButton.Text = 'Test Connection'
    $SMTPConnectionButton.Add_Click({
        Update-Log "Testing connection to [$($SMTPServerTextBox.Text)]..." -NoNewLine
        if (Test-Connection $SMTPServerTextBox.Text -Quiet) {
            Update-Log "reachable."
            $SMTPConnectionCheckBox.Checked = $true
        } else {
            Update-Log "unreachable." -Color 'Yellow'
            $SMTPConnectionCheckBox.Checked = $false
        }
    })
    $SMTPServerGroupBox.Controls.Add($SMTPConnectionButton)

    # SMTP server reachable check box
    $SMTPConnectionCheckBox = New-Object System.Windows.Forms.CheckBox
    $SMTPConnectionCheckBox.Enabled = $false
    $SMTPConnectionCheckBox.Text = 'Reachable'
    $SMTPConnectionCheckBox.Location = New-Object System.Drawing.Size(135, 50) 
    $SMTPConnectionCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $SMTPServerGroupBox.Controls.Add($SMTPConnectionCheckBox)

    # If email is enabled, check if SMTP server is reachable
    if ($DefaultEmailEnabled -and -not (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
        Update-Log "Email disabled because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
        $SMTPConnectionCheckBox.Checked = $false
    } elseif ($DefaultEmailEnabled -and (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
        Update-Log "SMTP server [$($SMTPServerTextBox.Text)] is reachable."
        $SMTPConnectionCheckBox.Checked = $true
    }

    # Email sender group box
    $EmailSenderGroupBox = New-Object System.Windows.Forms.GroupBox
    $EmailSenderGroupBox.Location = New-Object System.Drawing.Size(10, 150)
    $EmailSenderGroupBox.Size = New-Object System.Drawing.Size(220, 50)
    $EmailSenderGroupBox.Text = 'Email Sender'
    $EmailSettingsTabPage.Controls.Add($EmailSenderGroupBox)

    # Email sender text box
    $EmailSenderTextBox = New-Object System.Windows.Forms.TextBox
    $EmailSenderTextBox.Location = New-Object System.Drawing.Size(5, 20) 
    $EmailSenderTextBox.Size = New-Object System.Drawing.Size(210, 25)
    $EmailSenderTextBox.Text = $DefaultEmailSender
    $EmailSenderGroupBox.Controls.Add($EmailSenderTextBox)

    # Email recipients selection group box
    $EmailRecipientsGroupBox = New-Object System.Windows.Forms.GroupBox
    $EmailRecipientsGroupBox.Location = New-Object System.Drawing.Size(10, 230)
    $EmailRecipientsGroupBox.Size = New-Object System.Drawing.Size(220, 230)
    $EmailRecipientsGroupBox.Text = 'Email Recipients'
    $EmailSettingsTabPage.Controls.Add($EmailRecipientsGroupBox)
    
    # Email recipients data table
    $EmailRecipientsDataGridView = New-Object System.Windows.Forms.DataGridView
    $EmailRecipientsDataGridView.Location = New-Object System.Drawing.Size(5, 20)
    $EmailRecipientsDataGridView.Size = New-Object System.Drawing.Size(210, 170)
    $EmailRecipientsDataGridView.ReadOnly = $true
    $EmailRecipientsDataGridView.AllowUserToAddRows = $false
    $EmailRecipientsDataGridView.AllowUserToResizeRows = $false
    $EmailRecipientsDataGridView.AllowUserToResizeColumns = $false
    $EmailRecipientsDataGridView.MultiSelect = $false
    $EmailRecipientsDataGridView.ColumnCount = 1
    $EmailRecipientsDataGridView.AutoSizeColumnsMode = 'Fill'
    $EmailRecipientsDataGridView.ColumnHeadersVisible = $false
    $EmailRecipientsDataGridView.RowHeadersVisible = $false
    $EmailRecipientsGroupBox.Controls.Add($EmailRecipientsDataGridView)

    # Add default email addresses to data grid view
    foreach ($Email in $DefaultEmailRecipients) { $EmailRecipientsDataGridView.Rows.Add($Email) }

    # Remove email recipient button
    $RemoveEmailRecipientButton = New-Object System.Windows.Forms.Button
    $RemoveEmailRecipientButton.Location = New-Object System.Drawing.Size(0, 150)
    $RemoveEmailRecipientButton.Size = New-Object System.Drawing.Size(20, 20)
    $RemoveEmailRecipientButton.Text = '-'
    $RemoveEmailRecipientButton.Font = 'Consolas, 14'
    $RemoveEmailRecipientButton.Add_Click({
        # Remove selected cell from Email Recipients data grid view
        $CurrentCell = $EmailRecipientsDataGridView.CurrentCell
        Update-Log "Removed [$($CurrentCell.Value)] from email recipients."
        $CurrentRow = $EmailRecipientsDataGridView.Rows[$CurrentCell.RowIndex]
        $EmailRecipientsDataGridView.Rows.Remove($CurrentRow)
    })
    $EmailRecipientsDataGridView.Controls.Add($RemoveEmailRecipientButton)

    # Add email recipient button
    $AddEmailRecipientButton = New-Object System.Windows.Forms.Button
    $AddEmailRecipientButton.Location = New-Object System.Drawing.Size(20, 150)
    $AddEmailRecipientButton.Size = New-Object System.Drawing.Size(20, 20)
    $AddEmailRecipientButton.Text = '+'
    $AddEmailRecipientButton.Font = 'Consolas, 14'
    $AddEmailRecipientButton.Add_Click({
        Update-Log "Adding to email recipients: $($EmailRecipientToAddTextBox.Text)."
        $EmailRecipientsDataGridView.Rows.Add($EmailRecipientToAddTextBox.Text)
    })
    $EmailRecipientsDataGridView.Controls.Add($AddEmailRecipientButton)

    # Email recipient to add text box
    $EmailRecipientToAddTextBox = New-Object System.Windows.Forms.TextBox
    $EmailRecipientToAddTextBox.Location = New-Object System.Drawing.Size(5, 200) 
    $EmailRecipientToAddTextBox.Size = New-Object System.Drawing.Size(210, 25)
    $EmailRecipientToAddTextBox.Text = 'Recipient@To.Add'
    $EmailRecipientsGroupBox.Controls.Add($EmailRecipientToAddTextBox)

    # Send test email button
    $TestEmailButton = New-Object System.Windows.Forms.Button
    $TestEmailButton.Location = New-Object System.Drawing.Size(300, 400)
    $TestEmailButton.Size = New-Object System.Drawing.Size(100, 40)
    $TestEmailButton.Font = New-Object System.Drawing.Font('Calibri', 14, [System.Drawing.FontStyle]::Bold)
    $TestEmailButton.Text = 'Test Email'
    $TestEmailButton.Add_Click({ Test-Email })
    $EmailSettingsTabPage.Controls.Add($TestEmailButton)

    # Debug button
    $DebugLabel = New-Object System.Windows.Forms.Label
    $DebugLabel.Location = New-Object System.Drawing.Size(980, 500)
    $DebugLabel.Size = New-Object System.Drawing.Size(10, 15)
    $DebugLabel.Text = '?'
    $DebugLabel.Add_Click({
        if ($TabControl.SelectedIndex -eq 0) {
            Save-UserState -Debug
        } elseif ($TabControl.SelectedIndex -eq 1) {
            Load-UserState -Debug
        }
    })
    $Form.Controls.Add($DebugLabel)

    # Test if user is using an admin account
    Test-UserAdmin

    # Test the version of PowerShell and disable incompatible features
    Test-PSVersion

    # Get the path to the USMT files
    Get-USMT

    # Show our form
    $Form.Add_Shown({$Form.Activate()})
    $Form.ShowDialog() | Out-Null
}