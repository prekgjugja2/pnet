param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Url = 'http://localhost/pnet/agent.php',
    [int]$IntervalSec = 3
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$engine = Join-Path $root 'engine\build\pnet_scan.exe'
if (-not (Test-Path $engine)) {
    Write-Error "PNet engine not found at $engine. Run engine\build.bat first."
}

Write-Host "PNet agent reporting to $Url every ${IntervalSec}s"
Write-Host "Press Ctrl+C to stop."

while ($true) {
    try {
        $raw = & $engine --monitor --json 2>$null
        if (-not $raw) { Start-Sleep -Seconds $IntervalSec; continue }
        $snap = $raw | ConvertFrom-Json
        if (-not $snap.ok) { Start-Sleep -Seconds $IntervalSec; continue }

        $apps = @()
        foreach ($app in ($snap.apps | Select-Object -First 40)) {
            $apps += @{
                name = [string]$app.name
                down_bps = 0
                up_bps = 0
                tcp = [int]$app.tcp
                udp = [int]$app.udp
                remote_public = [int]$app.remote_public
            }
        }

        $body = @{
            token = $Token
            ip = [string]$snap.local_ip
            hostname = $env:COMPUTERNAME
            bytes_in = [int64]$snap.bytes_in
            bytes_out = [int64]$snap.bytes_out
            apps = $apps
        } | ConvertTo-Json -Depth 6 -Compress

        Invoke-RestMethod -Uri $Url -Method Post -Body $body -ContentType 'application/json; charset=utf-8' | Out-Null
        Write-Host ("[{0}] reported {1} apps" -f (Get-Date -Format 'HH:mm:ss'), $apps.Count)
    } catch {
        Write-Warning $_.Exception.Message
    }
    Start-Sleep -Seconds $IntervalSec
}
