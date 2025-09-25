$Pfad = "\\contoso.local\share\folder\$env:COMPUTERNAME-$env:USERNAME.txt"

#region Windows Build
$Build = (Get-CimInstance Win32_OperatingSystem).Caption + `
    ", Version " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name DisplayVersion).DisplayVersion + `
    " (Build " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name CurrentBuild).CurrentBuild + `
    "." + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name UBR).UBR + ")"
Set-Content -Path $Pfad -Value $Build
#endregion Windows Build


#region PartitionStyle
$PartitionStyle = (Get-Disk -Number 0).PartitionStyle
Add-Content -Path $Pfad -Value $PartitionStyle
#endregion PartitionStyle


#region PSDrive
$PSDrive = Get-PSDrive -PSProvider FileSystem | Format-Table -AutoSize | Out-String
Add-Content -Path $Pfad -Value $PSDrive
#endregion PSDrive


#region NetAdapter
$DnsClientServerAddress = Get-NetAdapter | Sort-Object -Property Name | Out-String
Add-Content -Path $Pfad -Value $DnsClientServerAddress
#endregion NetAdapter


#region NetIPAddress
$DnsClientServerAddress = Get-NetIPAddress | ? AddressFamily -EQ 2 | Sort-Object -Property InterfaceAlias | Format-Table -Property InterfaceAlias,IPAddress -AutoSize | Out-String
Add-Content -Path $Pfad -Value $DnsClientServerAddress
#endregion NetIPAddress


#region DnsClientServerAddress
$DnsClientServerAddress = Get-DnsClientServerAddress | ? AddressFamily -EQ 2 | Sort-Object -Property InterfaceAlias | Out-String
Add-Content -Path $Pfad -Value $DnsClientServerAddress
#endregion DnsClientServerAddress


#region local users
$LocalUser = Get-LocalUser | ? Name -ne "DefaultAccount" | Select-Object -Property Name,Enabled | Out-String
Add-Content -Path $Pfad -Value $LocalUser
#endregion local users


#region local administrator group members
$LocalAdminGroup = Get-LocalGroup -SID S-1-5-32-544 | Get-LocalGroupMember | Out-String
Add-Content -Path $Pfad -Value $LocalAdminGroup
#endregion local administrator group members


#region printer
$Printer = Get-Printer | Where-Object { $_.Name -ne "Microsoft XPS Document Writer" -and $_.Name -ne "Microsoft Print to PDF"} | Select-Object -Property Name,Type,PortName | Out-String
Add-Content -Path $Pfad -Value $Printer
#endregion printer


#region default printer
$DefaultPrinter = Get-WmiObject -Query " SELECT * FROM Win32_Printer WHERE Default=$true"
Add-Content -Path $Pfad -Value $DefaultPrinter
#endregion default printer
