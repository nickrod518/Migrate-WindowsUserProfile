# Migrate-WindowsUserProfile
Migrate Windows user profile to a new machine using Microsoft USMT with a PowerShell GUI.

## Setup
This requires that the USMT binaries are already present on the machine or a network accessible location. The easiest way to acquire these is to download and install the Windows ADK from https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit, and browse to the folder that contains scanstate.exe and loadstate.exe (usually C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\User State Migration Tool), and make a copy. For convenience sake, I've made the binaries available in a zip file in this repo. Unzip the contents of USMT.zip into the same directory as the script or into any other directory as long as you update the config.

Review the Config.ps1 file and make any changes to fit your needs.

## Output
You can specify the path that you want the logs and migration files to save to in the config file using the $MigrationStorePath variable (the default location is C:\TEMP\MigrationStore). You will see the load and scan state logs in that same folder named scan_progress.log and load_progress.log respectively. If you enter a new computer name the migration data will be saved on the new computer in the $MigrationStorePath directory in a folder with the same name as the old computer. You can change this location on the Old Computer tab in the Save State Destination section.

## Old Computer tab options
![alt OldComputerSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/OldComputer.png)

## New Computer tab options
![alt NewComputerSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/NewComputer.png)

## Email Settings tab options
![alt EmailSettings](https://github.com/nickrod518/Migrate-WindowsUserProfile/blob/master/images/EmailSettings.png)
