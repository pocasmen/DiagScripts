# Network data collection module for ECG Diagnostic
# Collects network adapter, DNS, latency, and Wi-Fi details

function Invoke-CollectionNetwork {
    param(
        [int]$PingCount = 20
    )

    Show-Step "A auditar rede: integridade (proxy, hosts, NCSI), latencia e Wi-Fi..."

    Invoke-Step "Network.Integrity" {
        $ncsi = Invoke-TimedStep "Network.NCSI" {
            try {
                $req = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
                return $req.Content
            } catch { return "" }
        } -TimeoutSec 5

        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $suspHosts = @()
        if (Test-Path $hostsPath) {
            $lines = Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#]' }
            $suspHosts = @($lines | Where-Object { $_ -match 'microsoft|windowsupdate|virustotal|defender' })
        }
        
        $proxyEnabled = $false
        try { $proxyEnabled = ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop).ProxyEnable -eq 1) } catch { }

        $Report.Facts.NetworkIntegrity = [ordered]@{
            NCSI_ConnectTest_OK = [bool]($ncsi -match 'Microsoft Connect Test')
            SuspiciousHostsEntries = $suspHosts
            ProxyEnabled = $proxyEnabled
        }
    }

    $NetFacts = [ordered]@{
        AdapterActive = "Nenhum"; IsVirtualAdapter = $null; PhysicalMedia = $null; LinkSpeedMbps = $null
        GatewayIP = $null; GatewayPing = $false; DNSResolution = $false; InternetTcp443 = $false
        IPv4 = @(); IsApipa = $false; DnsServers = @(); DnsServerTests = @()
        Latency = [ordered]@{ Gateway = $null; Internet = $null }
        Statistics = $null; WiFiDetails = $null
    }
    $Report.Facts.Network = $NetFacts

    Invoke-Step "Network" {
        $routes = @()
        try {
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ForEach-Object {
                $ifm = (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
                [pscustomobject]@{ IfIndex = $_.InterfaceIndex; NextHop = $_.NextHop; Metric = ([int]$_.RouteMetric + [int]$ifm) }
            } | Sort-Object Metric)
        } catch { }
        $best = $routes | Select-Object -First 1
        $adapter = $null; $gw = $null
        if ($best) { $adapter = Get-NetAdapter -InterfaceIndex $best.IfIndex -ErrorAction SilentlyContinue; $gw = $best.NextHop }
        if (-not $adapter) { $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual } | Select-Object -First 1 }
        if (-not $adapter) { return }

        $NetFacts.AdapterActive    = $adapter.InterfaceAlias
        $NetFacts.IsVirtualAdapter = [bool]$adapter.Virtual
        $NetFacts.PhysicalMedia    = "$($adapter.PhysicalMediaType)"
        $NetFacts.LinkSpeedMbps    = if ($adapter.Speed) { [math]::Round([double]$adapter.Speed / 1e6, 0) } else { $null }
        $NetFacts.GatewayIP        = $gw

        $ips = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.IPAddress)" })
        $NetFacts.IPv4 = $ips
        $NetFacts.IsApipa = [bool](@($ips | Where-Object { $_ -like '169.254.*' }).Count)

        $st = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
        if ($st) {
            $NetFacts.Statistics = [ordered]@{
                ReceivedUnicastPackets = [int64]$st.ReceivedUnicastPackets; SentUnicastPackets = [int64]$st.SentUnicastPackets
                ReceivedDiscardedPackets = [int64]$st.ReceivedDiscardedPackets; ReceivedPacketErrors = [int64]$st.ReceivedPacketErrors
                OutboundDiscardedPackets = [int64]$st.OutboundDiscardedPackets; OutboundPacketErrors = [int64]$st.OutboundPacketErrors
            }
        }

        if ($gw -and $gw -ne '0.0.0.0') {
            $NetFacts.Latency.Gateway = Test-PingTarget -Target $gw -Count $PingCount
            $NetFacts.GatewayPing = ($NetFacts.Latency.Gateway.Received -gt 0)
        }
        $NetFacts.Latency.Internet = Test-PingTarget -Target '1.1.1.1' -Count $PingCount

        try {
            if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                $dnsTest = Resolve-DnsName -Name "www.microsoft.com" -Type A -DnsOnly -ErrorAction Stop
            } else { $dnsTest = [System.Net.Dns]::GetHostAddresses("www.microsoft.com") }
            if ($dnsTest) { $NetFacts.DNSResolution = $true }
        } catch { }

        $servers = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Select-Object -First 3)
        $NetFacts.DnsServers = $servers
        $tests = @()
        foreach ($srv in $servers) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew(); $ok = $false
            try { $null = Resolve-DnsName -Name 'www.microsoft.com' -Server $srv -Type A -DnsOnly -QuickTimeout -ErrorAction Stop; $ok = $true } catch { }
            $sw.Stop()
            $tests += [ordered]@{ Server = $srv; Ok = $ok; Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 0) }
        }
        $NetFacts.DnsServerTests = $tests

        $tcp = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect("1.1.1.1", 443, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp.Connected) { $tcp.EndConnect($iar); $NetFacts.InternetTcp443 = $true }
        } catch { } finally { if ($tcp) { $tcp.Close(); $tcp.Dispose() } }

        $wl = netsh wlan show interfaces 2>$null
        if ($wl) {
            $ssid = Get-TextField $wl '^\s*SSID\s*:\s*(.+)$'
            if ($ssid) {
                $sig = Get-TextField $wl '^\s*(?:Sinal|Signal)\s*:\s*(\d+)'
                $chan = Get-TextField $wl '^\s*(?:Channel|Canal)\s*:\s*(\d+)'
                $band = Get-TextField $wl '^\s*(?:Band|Banda)\s*:\s*(.+)$'
                if (-not $band -and $chan) { $band = if ([int]$chan -ge 36) { '5 GHz (inferido)' } else { '2.4 GHz (inferido)' } }
                $rx = Get-TextField $wl '^\s*(?:Receive rate|Taxa de rece.{1,3}o)\s*\(Mbps\)\s*:\s*([\d.,]+)'
                $tx = Get-TextField $wl '^\s*(?:Transmit rate|Taxa de transmiss.{1,3}o)\s*\(Mbps\)\s*:\s*([\d.,]+)'
                $NetFacts.WiFiDetails = [ordered]@{
                    SSID = $ssid; SignalPct = if ($sig) { [int]$sig } else { $null }
                    RadioType = Get-TextField $wl '^\s*(?:Radio type|Tipo de r.{1,2}dio)\s*:\s*(.+)$'
                    Channel = $chan; Band = $band; ReceiveMbps = $rx; TransmitMbps = $tx
                }
            }
        }
    }
}
