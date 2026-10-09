param(
    [string]$BlocklistPath = '',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$begin = '# BEGIN PNet block list'
$end = '# END PNet block list'

if (-not (Test-Path -LiteralPath $hostsPath)) {
    Write-Error "Hosts file not found at $hostsPath"
}

$existing = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
$out = New-Object System.Collections.Generic.List[string]
$inPnet = $false
foreach ($line in $existing) {
    if ($line -eq $begin) {
        $inPnet = $true
        continue
    }
    if ($line -eq $end) {
        $inPnet = $false
        continue
    }
    if (-not $inPnet) {
        [void]$out.Add($line)
    }
}

while ($out.Count -gt 0 -and [string]::IsNullOrWhiteSpace($out[$out.Count - 1])) {
    $out.RemoveAt($out.Count - 1)
}

if ($Remove) {
    Set-Content -LiteralPath $hostsPath -Value $out -Encoding Ascii
    ipconfig /flushdns | Out-Null
    Write-Output 'removed'
    exit 0
}

if (-not $BlocklistPath -or -not (Test-Path -LiteralPath $BlocklistPath)) {
    Write-Error 'Block list file missing.'
}

$entries = New-Object System.Collections.Generic.List[string]
Get-Content -LiteralPath $BlocklistPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -match '^\s*0\.0\.0\.0\s+(\S+)') {
        [void]$entries.Add("0.0.0.0 $($Matches[1])")
    }
}

if ($entries.Count -lt 1) {
    Write-Error 'Block list has no domains to apply.'
}

[void]$out.Add('')
[void]$out.Add($begin)
[void]$out.Add("# Applied by PNet $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
foreach ($entry in $entries) {
    [void]$out.Add($entry)
}
[void]$out.Add($end)

Set-Content -LiteralPath $hostsPath -Value $out -Encoding Ascii
ipconfig /flushdns | Out-Null
Write-Output "applied $($entries.Count)"
