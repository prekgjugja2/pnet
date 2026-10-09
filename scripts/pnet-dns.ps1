param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('status', 'start', 'stop', 'ensure', 'push-wifi', 'pull-wifi', 'restore-wifi')]
    [string]$Action,

    [string]$WorkDir = '',
    [string]$FilterPath = '',
    [string]$SourceDir = '',
    [string]$PasswordHash = '',
    [string]$DnsServer = '127.0.0.1',
    [string]$ReleaseUrl = 'https://github.com/AdguardTeam/AdGuardHome/releases/latest/download/AdGuardHome_windows_amd64.zip'
)

$ErrorActionPreference = 'Stop'

function Write-Json($obj) {
    $obj | ConvertTo-Json -Compress -Depth 6
}

function Get-LanIPv4 {
    $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike '127.*' -and
            $_.PrefixOrigin -ne 'WellKnown' -and
            (
                $_.IPAddress -like '192.168.*' -or
                $_.IPAddress -like '10.*' -or
                ($_.IPAddress -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.')
            )
        }
    $ranked = foreach ($addr in $adapters) {
        $if = Get-NetAdapter -InterfaceIndex $addr.InterfaceIndex -ErrorAction SilentlyContinue
        $name = [string]($if.Name)
        $desc = [string]($if.InterfaceDescription)
        $virtual = ($name -match 'vEthernet|WSL|Hyper-V|Docker|Virtual|Loopback|VMware|VirtualBox|VPN|Tailscale|ZeroTier') -or
            ($desc -match 'Hyper-V|WSL|Virtual|VPN|TAP|TUN|VMware|VirtualBox|Docker')
        $score = 100
        if ($addr.IPAddress -like '192.168.*') { $score = 0 }
        elseif ($addr.IPAddress -like '10.*') { $score = 1 }
        else { $score = 2 }
        if ($virtual) { $score += 50 }
        if ($if -and $if.Status -ne 'Up') { $score += 20 }
        [pscustomobject]@{
            IP = [string]$addr.IPAddress
            Score = $score
            Metric = [int]($addr.InterfaceMetric)
        }
    }
    $best = $ranked | Sort-Object Score, Metric | Select-Object -First 1
    if ($best) { return $best.IP }
    return ''
}

if (-not $WorkDir) {
    $WorkDir = Join-Path $env:LOCALAPPDATA 'PNet\AdGuardHome'
}

$exe = Join-Path $WorkDir 'AdGuardHome.exe'
$yaml = Join-Path $WorkDir 'AdGuardHome.yaml'
$serviceName = 'AdGuardHome'
$webPort = 3000
$dnsPort = 53

function Test-AghHttp {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$webPort/control/status" -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -lt 200 -or $resp.StatusCode -ge 500) { return $false }
        $body = [string]$resp.Content
        return ($body -match 'version' -or $body -match 'dns_addresses' -or $body -match 'protection_enabled' -or $body -match '"running"')
    } catch {
        return $false
    }
}

function Get-ServiceState {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) { return 'missing' }
    return [string]$svc.Status
}

function Ensure-Firewall {
    $rule = 'PNet AdGuard Home DNS'
    $existing = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Protocol UDP -LocalPort $dnsPort | Out-Null
        New-NetFirewallRule -DisplayName "$rule TCP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $dnsPort | Out-Null
    }
}

function Ensure-Binary {
    if (Test-Path -LiteralPath $exe) { return }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $zip = Join-Path $env:TEMP ("AdGuardHome_windows_amd64_{0}.zip" -f [guid]::NewGuid().ToString('N'))
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $ReleaseUrl -OutFile $zip -UseBasicParsing
        $extract = Join-Path $env:TEMP ("agh_extract_{0}" -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $extract | Out-Null
        Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
        $found = Get-ChildItem -Path $extract -Recurse -Filter 'AdGuardHome.exe' | Select-Object -First 1
        if (-not $found) {
            throw 'AdGuardHome.exe missing from download.'
        }
        Copy-Item -LiteralPath $found.FullName -Destination $exe -Force
        $sibling = Split-Path -Parent $found.FullName
        Get-ChildItem -LiteralPath $sibling -File | ForEach-Object {
            if ($_.Name -ne 'AdGuardHome.exe') {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $WorkDir $_.Name) -Force
            }
        }
    } finally {
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    }
}

function Write-Config {
    param([string]$SourceDir)

    if ($SourceDir -and (Test-Path -LiteralPath (Join-Path $SourceDir 'AdGuardHome.yaml'))) {
        Copy-Item -LiteralPath (Join-Path $SourceDir 'AdGuardHome.yaml') -Destination $yaml -Force
    }

    $localFilter = Join-Path $WorkDir 'pnet-user-rules.txt'
    if ($FilterPath -and (Test-Path -LiteralPath $FilterPath)) {
        Copy-Item -LiteralPath $FilterPath -Destination $localFilter -Force
    } elseif ($SourceDir -and (Test-Path -LiteralPath (Join-Path $SourceDir 'pnet-user-rules.txt'))) {
        Copy-Item -LiteralPath (Join-Path $SourceDir 'pnet-user-rules.txt') -Destination $localFilter -Force
    } elseif (-not (Test-Path -LiteralPath $localFilter)) {
        Set-Content -LiteralPath $localFilter -Value "! PNet custom rules`r`n" -Encoding utf8
    }

    if (Test-Path -LiteralPath $yaml) {
        return
    }

    if (-not $PasswordHash) {
        throw 'PasswordHash is required for first-time AdGuard Home setup.'
    }

    # Prevent PowerShell from expanding $2y$... bcrypt dollars.
    $hashLiteral = $PasswordHash.Replace('$', '`$')
    $filterUri = ([Uri]$localFilter).AbsoluteUri
    $template = @"
bind_host: 127.0.0.1
bind_port: $webPort
users:
  - name: pnet
    password: __PNET_HASH__
auth_attempts: 5
block_auth_min: 15
http:
  address: 127.0.0.1:$webPort
  session_ttl: 720h
dns:
  bind_hosts:
    - 0.0.0.0
  port: $dnsPort
  anonymize_client_ip: false
  upstream_dns:
    - https://dns.cloudflare.com/dns-query
    - 1.1.1.1
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  protection_enabled: true
  ratelimit: 0
  cache_size: 4194304
  enable_dnssec: false
filtering:
  protection_enabled: true
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: false
  safebrowsing_enabled: false
  safesearch_enabled: false
querylog:
  enabled: true
  file_enabled: true
  interval: 24h
  size_memory: 1000
statistics:
  enabled: true
  interval: 24h
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: __PNET_FILTER__
    name: PNet custom blocks
    id: 2
  - enabled: false
    url: https://blocklistproject.github.io/Lists/porn.txt
    name: Adult sites
    id: 3
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
schema_version: 28
"@
    $content = $template.Replace('__PNET_HASH__', $PasswordHash).Replace('__PNET_FILTER__', $filterUri)
    Set-Content -LiteralPath $yaml -Value $content -Encoding utf8
}

function Install-Or-Start {
    Ensure-Binary
    Write-Config -SourceDir $SourceDir
    Ensure-Firewall
    $state = Get-ServiceState
    Push-Location $WorkDir
    try {
        if ($state -eq 'missing') {
            & $exe -s install -c $yaml -w $WorkDir | Out-Null
            Start-Sleep -Seconds 1
        }
        $state = Get-ServiceState
        if ($state -ne 'Running') {
            & $exe -s start -c $yaml -w $WorkDir | Out-Null
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        }
    } finally {
        Pop-Location
    }
    $ok = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-AghHttp) { $ok = $true; break }
        $svc = Get-ServiceState
        if ($svc -eq 'Running' -and $i -gt 5) { $ok = $true; break }
    }
    if (-not $ok -and (Get-ServiceState) -ne 'Running') {
        $running = Get-Process -Name 'AdGuardHome' -ErrorAction SilentlyContinue
        if (-not $running) {
            Start-Process -FilePath $exe -ArgumentList @('-c', $yaml, '-w', $WorkDir, '--no-check-update') -WorkingDirectory $WorkDir -WindowStyle Hidden
            Start-Sleep -Seconds 2
        }
    }
}

function Stop-Agh {
    $state = Get-ServiceState
    if ($state -ne 'missing') {
        Push-Location $WorkDir
        try {
            & $exe -s stop -c $yaml -w $WorkDir 2>$null | Out-Null
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        } finally {
            Pop-Location
        }
    }
    Get-Process -Name 'AdGuardHome' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Get-WifiAdapter {
    $wifi = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -eq 'Up' -and (
                $_.Name -match 'Wi-?Fi|Wireless|WLAN' -or
                $_.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN|802\.11'
            ) -and
            $_.Name -notmatch 'vEthernet|WSL|Hyper-V|Virtual|VMware|VirtualBox|Docker'
        } |
        Sort-Object -Property InterfaceMetric |
        Select-Object -First 1
    if ($wifi) { return $wifi }
    # Fallback: adapter that owns the preferred LAN IP
    $lan = Get-LanIPv4
    if ($lan) {
        $addr = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $lan -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($addr) {
            return Get-NetAdapter -InterfaceIndex $addr.InterfaceIndex -ErrorAction SilentlyContinue
        }
    }
    return $null
}

function Get-WifiDnsInfo {
    $adapter = Get-WifiAdapter
    if (-not $adapter) {
        return [ordered]@{
            adapter = ''
            dns = @()
            dhcp = $null
            pushed = $false
        }
    }
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue)
    $cfg = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $pushed = ($dns -contains '127.0.0.1') -or ($dns -contains $DnsServer)
    return [ordered]@{
        adapter = [string]$adapter.Name
        dns = @($dns | ForEach-Object { [string]$_ })
        dhcp = if ($cfg) { [bool]($cfg.Dhcp -eq 'Enabled') } else { $null }
        pushed = [bool]$pushed
    }
}

function Push-WifiDns {
    $adapter = Get-WifiAdapter
    if (-not $adapter) {
        throw 'No active Wi-Fi adapter found.'
    }
    $target = if ($DnsServer) { $DnsServer } else { '127.0.0.1' }
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @($target) -ErrorAction Stop
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    return Get-WifiDnsInfo
}

function Restore-WifiDns {
    $adapter = Get-WifiAdapter
    if (-not $adapter) {
        throw 'No active Wi-Fi adapter found.'
    }
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    return Get-WifiDnsInfo
}

function Get-StatusObject {
    $lan = Get-LanIPv4
    $svc = Get-ServiceState
    $proc = @(Get-Process -Name 'AdGuardHome' -ErrorAction SilentlyContinue)
    $hasBinary = Test-Path -LiteralPath $exe
    $running = ($svc -eq 'Running') -or ($proc.Count -gt 0)
    $http = $false
    if ($running) {
        $http = Test-AghHttp
    }
    $wifi = Get-WifiDnsInfo
    return [ordered]@{
        ok = $true
        running = [bool]$running
        service = $svc
        http = [bool]$http
        lan_ip = $lan
        dns_port = $dnsPort
        web_port = $webPort
        workdir = $WorkDir
        exe = $hasBinary
        filter_path = $FilterPath
        wifi_adapter = $wifi.adapter
        wifi_dns = $wifi.dns
        wifi_pushed = $wifi.pushed
    }
}

switch ($Action) {
    'status' {
        Write-Json (Get-StatusObject)
    }
    'ensure' {
        Ensure-Binary
        Write-Json (Get-StatusObject)
    }
    'start' {
        Install-Or-Start
        try { Push-WifiDns | Out-Null } catch { }
        Write-Json (Get-StatusObject)
    }
    'stop' {
        Stop-Agh
        try { Restore-WifiDns | Out-Null } catch { }
        Write-Json (Get-StatusObject)
    }
    'push-wifi' {
        $info = Push-WifiDns
        $status = Get-StatusObject
        $status.wifi_adapter = $info.adapter
        $status.wifi_dns = $info.dns
        $status.wifi_pushed = $info.pushed
        Write-Json $status
    }
    'pull-wifi' {
        $info = Get-WifiDnsInfo
        $status = Get-StatusObject
        $status.wifi_adapter = $info.adapter
        $status.wifi_dns = $info.dns
        $status.wifi_pushed = $info.pushed
        Write-Json $status
    }
    'restore-wifi' {
        $info = Restore-WifiDns
        $status = Get-StatusObject
        $status.wifi_adapter = $info.adapter
        $status.wifi_dns = $info.dns
        $status.wifi_pushed = $info.pushed
        Write-Json $status
    }
}
