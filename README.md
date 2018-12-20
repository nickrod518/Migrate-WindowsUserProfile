# Migrate-WindowsUserProfile
Migrate Windows user profile to a new machine using Microsoft USMT with a PowerShell GUI.

## Setup
This requires that the USMT binaries are already present on the machine or a network accessible location. The easiest way to acquire these is to download and install the Windows ADK from https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit, and browse to the folder that contains scanstate.exe and loadstate.exe (usually C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\User State Migration Tool), and make a copy. For convenience sake, I've made the binaries available in a zip file in this repo. Unzip the USMT.zip and place the amd64, arm64, and x86 folders inside USMT. This will make the USMT folder look like below.

.
+-- Invoke-USMTGUI.ps1
+-- USMT\
|   +-- amd64\
|   +-- arm64\
|   +-- Scripts\
|   +-- x86\
|   +-- Config.ps1

Review the USMT\Config.ps1 file and make any changes to fit your needs.

I recommend using my Create-EXEFromPS1 (https://github.com/nickrod518/Create-EXEFromPS1) to package the prepped migration tool for portability and ease of use. When you have [installed the module](https://docs.microsoft.com/en-us/powershell/developer/module/installing-a-powershell-module) you may package the project using the following command from an admin powershell session.

`New-EXEFromPS1 -PSScriptPath $PathToProject\Invoke-USMTGUI.ps1 -SupplementalDirectoryPath $PathToProject\USMT\`

## Output
You can specify the path that you want the logs and migration files to save to in the config file using the $MigrationStorePath variable (the default location is C:\TEMP\MigrationStore). You will see the load and scan state logs in that same folder named scan_progress.log and load_progress.log respectively. If you enter a new computer name the migration data will be saved on the new computer in the $MigrationStorePath directory in a folder with the same name as the old computer. You can change this location on the Old Computer tab in the Save State Destination section.

## Old Computer tab options
![alt OldComputerSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/OldComputer.png)

## New Computer tab options
![alt NewComputerSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/NewComputer.png)

## Email Settings tab options
![alt EmailSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/EmailSettings.png)

## Scripts tab options
![alt ScriptsSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/Scripts.png)