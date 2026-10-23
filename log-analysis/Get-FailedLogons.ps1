<#
.SYNOPSIS
    Summarizes failed Windows logons (Event ID 4625) to spot brute-force and password-spraying activity.

.DESCRIPTION
    Reads the Security event log, groups failed logons by source IP and target account,
    and flags sources over a threshold. Also decodes the failure Status code (e.g. bad
    password vs. unknown user vs. locked account) so triage is faster.

    MITRE ATT&CK: T1110 - Brute Force

    Run from an elevated PowerShell prompt (reading the Security log requires admin).

.EXAMPLE
    .\Get-FailedLogons.ps1
.EXAMPLE
    .\Get-FailedLogons.ps1 -Hours 48 -Threshold 10 -CsvPath .\failed_logons.csv
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$Threshold = 5,
    [string]$CsvPath
)

$StatusCodes = @{
    '0xC000006A' = 'Bad password'
    '0xC0000064' = 'Unknown username'
    '0xC0000234' = 'Account locked out'
    '0xC0000072' = 'Account disabled'
    '0xC000006F' = 'Outside allowed logon hours'
    '0xC0000071' = 'Password expired'
    '0xC0000193' = 'Account expired'
    '0xC000006D' = 'Bad username or auth info'
}

$LogonTypes = @{ 2 = 'Interactive'; 3 = 'Network'; 7 = 'Unlock'; 8 = 'NetworkCleartext'; 10 = 'RemoteInteractive (RDP)' }

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = (Get-Date).AddHours(-$Hours)
    } -ErrorAction Stop
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "[+] No failed logons in the last $Hours hour(s)." -ForegroundColor Green
        return
    }
    Write-Error "Could not read the Security log. Run PowerShell as Administrator. $_"
    return
}

$records = foreach ($e in $events) {
    $xml  = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    $sub = "$($data['SubStatus'])".ToUpper() -replace '^0X', '0x'
    $type = [int]$data['LogonType']
    [pscustomobject]@{
        Time      = $e.TimeCreated
        Account   = "$($data['TargetDomainName'])\$($data['TargetUserName'])"
        SourceIP  = if ($data['IpAddress'] -and $data['IpAddress'] -ne '-') { $data['IpAddress'] } else { 'local' }
        LogonType = if ($LogonTypes.ContainsKey($type)) { $LogonTypes[$type] } else { "$type" }
        Reason    = if ($StatusCodes.ContainsKey($sub)) { $StatusCodes[$sub] } else { $sub }
    }
}

Write-Host "`n[*] $($records.Count) failed logon(s) in the last $Hours hour(s)`n" -ForegroundColor Cyan

$bySource = $records | Group-Object SourceIP | Sort-Object Count -Descending | ForEach-Object {
    $accounts = ($_.Group.Account | Sort-Object -Unique)
    [pscustomobject]@{
        SourceIP       = $_.Name
        Failures       = $_.Count
        UniqueAccounts = $accounts.Count
        Pattern        = if ($accounts.Count -ge 5) { 'Password spraying?' } elseif ($_.Count -ge $Threshold) { 'Brute force?' } else { '' }
        FirstSeen      = ($_.Group.Time | Measure-Object -Minimum).Minimum
        LastSeen       = ($_.Group.Time | Measure-Object -Maximum).Maximum
        LogonTypes     = ($_.Group.LogonType | Sort-Object -Unique) -join ', '
        TopReason      = ($_.Group | Group-Object Reason | Sort-Object Count -Descending | Select-Object -First 1).Name
    }
}

$flagged = $bySource | Where-Object { $_.Failures -ge $Threshold }
if ($flagged) {
    Write-Host "[!] Sources at or above threshold ($Threshold):" -ForegroundColor Red
    $flagged | Format-Table -AutoSize
} else {
    Write-Host "[+] No source exceeded the threshold." -ForegroundColor Green
}

Write-Host "[*] Most-targeted accounts:" -ForegroundColor Cyan
$records | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 Count, Name | Format-Table -AutoSize

if ($CsvPath) {
    $bySource | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "[*] Summary exported to $CsvPath"
}
