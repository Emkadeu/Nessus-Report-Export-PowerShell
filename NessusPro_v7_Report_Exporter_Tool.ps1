<#
ScriptName: NessusPro_v7_Report_Exporter_Tool.ps1
PSVersion:  7
Purpose:    Powershell script that use REST methods to obtain report automation tasks.
Created:    Sept 2018.
Comments:
Notes:      -Script must be run with ACL that has proxy access if external facing Nessus.io servers are targeted
            -Ensure execution policy is set to unrestricted (Requires Administrative ACL)
Author:     Paperclips.
Email:      Pwd9000@hotmail.co.uk
TechNet:    https://gallery.technet.microsoft.com/site/search?f[0].Type=User&f[0].Value=paperclips
Github:     https://github.com/Pwd9000-ML#>

#------------------Allow Selfsign Cert + workaround force TLS 1.2 connections---------------------

#Ensure correct execution policy is set to run script. Administrative permission is required to Set-ExecutionPolicy.
#Set-ExecutionPolicy Bypass

[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#------------------Input Variables-----------------------------------------------------------------
$Baseurl = Read-Host "Enter Nessus Scanner URL + Port (e.g. https://NessusServerFQDN:8834)"
$Username = Read-Host "Enter login username (e.g. Administrator)"
$PasswordResponse = Read-Host "Enter Password" -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordResponse))
$ContentType = "application/json"
$POSTMethod = 'POST'
$GETMethod = 'GET'

#------------------Create Json Object--------------------------------------------------------------
$UserNameBody = convertto-json (New-Object PSObject -Property @{username = $username; password = $Password})

#------------------Create URI's--------------------------------------------------------------------
$SessionAPIurl = "/session"
$ScansAPIurl = "/scans"
$FolderAPIurl = "/folders"
$SessionUri = $baseurl + $SessionAPIurl
$ScansUri = $baseurl + $ScansAPIurl
$FolderUri = $Baseurl + $FolderAPIurl

#------------------Stage props to obtain session token (Parameters)--------------------------------
$session = @{
    Uri         = $SessionUri
    ContentType = $ContentType
    Method      = $POSTMethod
    Body        = $UserNameBody
}

#------------------Commit session props for token header X-cookie----------------------------------
$TokenResponse = Invoke-RestMethod @session -SkipCertificateCheck
if ($TokenResponse) {
    $Header = @{"X-Cookie" = "token=" + $TokenResponse.token}
}
else {
    Write-host ""
    Write-host "Error occured obtaining session token. Script Terminating... Please ensure Username and Password Correct." -ForegroundColor Red
    Start-Sleep -s 20
    Exit
}

# list folders
$Folders = (Invoke-RestMethod -Uri $FolderUri -Headers $Header -Method $GETMethod -ContentType "application/json"  -SkipCertificateCheck).folders |
    Select-Object @{Name = "Folder Name"; Expression = { $_.Name } },
@{Name = "Id"; Expression = { $_.id } } |
    Format-Table -AutoSize

$Folders
$folder = Read-Host "Enter id of the folder? (number))"


#------------------Output completed scans----------------------------------------------------------
$Scanscompleted = (Invoke-RestMethod -Uri $ScansUri -Headers $Header -Method $GETMethod -ContentType "application/json"  -SkipCertificateCheck).scans |
				Where-Object {$_.status -eq "completed" -and $_.folder_id -eq $folder} |
				Select-Object @{Name = "Scan Name"; Expression = {$_.Name}},
@{Name = "Scan Status"; Expression = {$_.Status}},
@{Name = "Id"; Expression = {$_.id}} |
    Format-Table -AutoSize
$Scansnotcompleted = (Invoke-RestMethod -Uri $ScansUri -Headers $Header -Method $GETMethod -ContentType "application/json" -SkipCertificateCheck).scans |
				Where-Object {$_.status -ne "completed" -and $_.folder_id -eq $folder} |
				Select-Object @{Name = "Scan Name"; Expression = {$_.Name}},
@{Name = "Scan Status"; Expression = {$_.Status}},
@{Name = "Id"; Expression = {$_.id}} |
    Format-Table -AutoSize

Write-Host "-------------------------------------------------------" -ForegroundColor Green
Write-Host "-The following Scans are Completed and can be exported-" -ForegroundColor Green
Write-Host "-------------------------------------------------------" -ForegroundColor Green
$Scanscompleted

Write-Host "---------------------------------------------------------------------" -ForegroundColor Red
Write-Host "-The following Scans have issues and cannot be exported autonomously-" -ForegroundColor Red
Write-Host "---------------------------------------------------------------------" -ForegroundColor Red
$Scansnotcompleted

#------------------Export Completed Scans (Y/N)----------------------------------------------------
$answerexport = Read-Host "Do you want to export the completed Scans? (Y/N)"
If ($answerexport -eq "Y") {
    $continue = $True
    Write-Host "----------------------------"
    Write-Host "-Enter Report Export Format-"
    Write-Host "----------------------------"
    Write-Host ""
    Write-Host "The ""nessus"" format selection will export reports to XML"
    $Format = Read-Host "Enter selection: (nessus OR csv OR pdf)"
    $ExportBody = convertto-json (New-Object PSObject -Property @{
    format = "$Format"
    template_id = "121"
        "filter.0.quality"="neq"
        "filter.0.filter"="severity"
        "filter.0.value"="0"
        "filter.1.quality" = "neq"
        "filter.1.filter"  = "severity"
        "filter.1.value"   = "1"
        "filter.search_type"="and"
})


    Write-Host "Checking Status...."

    #------------------POST Export Requests------------------------------------------------------------
    $StatusArray = @()
    (Invoke-RestMethod -Uri $ScansUri -Headers $Header -Method $GETMethod -ContentType "application/json" -SkipCertificateCheck).scans |
        Where-Object {$_.status -eq "completed" -and $_.folder_id -eq $folder} | select-object id, name |
        ForEach-Object {
        $Exportfile = @{
            Uri         = "$ScansUri" + "/" + $_.id + "/export"
            ContentType = $ContentType
            Headers     = $Header
            Method      = $POSTMethod
            Body        = $ExportBody
        }
        $file = (Invoke-RestMethod @Exportfile -SkipCertificateCheck).file
        $ScanName = $_.name
        $StatusUri = "$ScansUri" + "/" + $_.id + "/export/" + "$file" + "/status"
        $DownloadUri = "$ScansUri" + "/" + $_.id + "/export/" + "$file" + "/download"
        $StatusArray += [pscustomobject]@{ScanName = $ScanName; StatusUri = $StatusUri; DownloadUri = $DownloadUri}
    }

    #------------------Check Status of Export requests-------------------------------------------------
    Start-Sleep -s 125
    $Count = 0
    $StatusArray.StatusUri | ForEach-Object {
        (Invoke-RestMethod -Uri "$_" -ContentType $ContentType -Headers $Header -Method $GETMethod -SkipCertificateCheck).status |
            ForEach-Object {
            If ($_ -ne "ready") {
                $Count = $Count + 1
                Write-Host "Scan $Count not Ready. Scan is $_. Pausing for 30seconds..." -ForegroundColor Red
                Start-Sleep -s 30
            }
            else {
                $Count = $Count + 1
                Write-Host "Scan $Count ready for export" -ForegroundColor Green
            }
        }
    }
    Write-Host ""
    Write-Host "Initiating Scan Export. Please wait for WebRequests to Complete..." -ForegroundColor Green
    Write-Host ""
    Start-Sleep -s 5

    #------------------Download the Reports------------------------------------------------------------
    $ExportUri = $StatusArray.DownloadUri
    $outputs = $StatusArray.ScanName
    foreach ($i in 0..($ExportUri.Count - 1)) {
        Invoke-WebRequest -Uri $ExportUri[$i] -ContentType $ContentType -Headers $Header -Method $GETMethod -OutFile "C:\Temp\$($outputs[$i]).$format" -SkipCertificateCheck
    }
    Get-childitem c:\Temp\* -include *.nessus -Recurse | Rename-Item -NewName {$_.name -replace 'nessus', 'xml'}
    Write-Host ""
    Write-Host "Scans have been exported to ""C:\Temp\""" -ForegroundColor Green
    Start-Sleep -s 10
}
else {
    Write-Host "You selected not to export completed Scans"
    Write-Host "This script will Terminate in 10seconds"
    Start-Sleep -s 10
}
#------------------Script END----------------------------------------------------------------------
