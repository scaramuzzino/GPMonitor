<#
  gp-monitor probe (Windows) — READ-ONLY.
  Emette su stdout un unico documento JSON con lo STESSO schema della sonda Linux/macOS:
  RAM, DISCO, RETE (contatori cumulativi), connessioni, container Docker (se presente)
  e metriche di sicurezza (SSH da Event Log; firewall/fail2ban non disponibili -> null).
  Solo cmdlet integrati (nessun modulo esterno). Pensato per girare come comando forzato
  in authorized_keys sull'OpenSSH Server di Windows.

  Requisiti: Windows 8/Server 2012+ (Get-NetTCPConnection/Get-NetAdapterStatistics),
  PowerShell 5.1+. Per leggere gli SSH falliti serve accesso al log Security
  (utente admin o nel gruppo "Event Log Readers").

  Nota agentless: come per macOS alcune metriche non esistono su questo OS e sono
  riportate come null (dato non disponibile), MAI come 0 (che significa "nessun evento").

  Autore: Stefano Scaramuzzino
#>
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$PROBE_VERSION = 3

function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }

function ToPct($s) {
    if ($null -eq $s) { return $null }
    $t = ("$s" -replace '%', '').Trim()
    $d = 0.0
    if ([double]::TryParse($t, [Globalization.NumberStyles]::Any, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return $null
}
function ToInt($s) {
    if ($null -eq $s) { return $null }
    $i = 0
    if ([int]::TryParse(("$s").Trim(), [ref]$i)) { return $i }
    return $null
}
function Cim($class, $filter) {
    # Get-CimInstance con fallback a WMI (host molto vecchi)
    try { if ($filter) { return Get-CimInstance -ClassName $class -Filter $filter -ErrorAction Stop } else { return Get-CimInstance -ClassName $class -ErrorAction Stop } }
    catch { try { if ($filter) { return Get-WmiObject -Class $class -Filter $filter -ErrorAction Stop } else { return Get-WmiObject -Class $class -ErrorAction Stop } } catch { return $null } }
}

# ---- CPU logiche (per normalizzare l'uso CPU dei container) ----
$cpus = [int]$env:NUMBER_OF_PROCESSORS
if ($cpus -lt 1) { $cs = Cim 'Win32_ComputerSystem'; if ($cs) { $cpus = [int]$cs.NumberOfLogicalProcessors } }
if ($cpus -lt 1) { $cpus = 1 }

# ---- RAM (Win32_OperatingSystem, valori in KB) + swap (pagefile, in MB) ----
$os = Cim 'Win32_OperatingSystem'
$total = 0; $avail = 0
if ($os) { $total = [int64]$os.TotalVisibleMemorySize * 1024; $avail = [int64]$os.FreePhysicalMemory * 1024 }
$swTotal = 0; $swUsed = 0
foreach ($pf in @(Cim 'Win32_PageFileUsage')) { if ($pf) { $swTotal += [int64]$pf.AllocatedBaseSize * 1MB; $swUsed += [int64]$pf.CurrentUsage * 1MB } }
$ram = [ordered]@{
    total = $total; available = $avail; used = [math]::Max(0, $total - $avail)
    swap_total = $swTotal; swap_used = $swUsed
}

# ---- DISCO (dischi fissi, DriveType=3) ----
$disk = New-Object System.Collections.ArrayList
foreach ($d in @(Cim 'Win32_LogicalDisk' 'DriveType=3')) {
    if (-not $d) { continue }
    $size = [int64]$d.Size; $free = [int64]$d.FreeSpace; $used = $size - $free
    $pct = if ($size -gt 0) { [math]::Round($used / $size * 100, 1) } else { 0 }
    [void]$disk.Add([ordered]@{ target = "$($d.DeviceID)"; fstype = "$($d.FileSystem)"; size = $size; used = $used; avail = $free; use_pct = $pct })
}

# ---- RETE (contatori cumulativi) ----
$net = New-Object System.Collections.ArrayList
$gotNet = $false
try {
    foreach ($n in @(Get-NetAdapterStatistics -ErrorAction Stop)) {
        $rxp = [int64]$n.ReceivedUnicastPackets + [int64]$n.ReceivedMulticastPackets + [int64]$n.ReceivedBroadcastPackets
        $txp = [int64]$n.SentUnicastPackets + [int64]$n.SentMulticastPackets + [int64]$n.SentBroadcastPackets
        [void]$net.Add([ordered]@{ iface = "$($n.Name)"; rx_bytes = [int64]$n.ReceivedBytes; rx_pkts = $rxp; tx_bytes = [int64]$n.SentBytes; tx_pkts = $txp })
        $gotNet = $true
    }
} catch { }
if (-not $gotNet) {
    foreach ($n in @(Cim 'Win32_PerfRawData_Tcpip_NetworkInterface')) {
        if (-not $n -or "$($n.Name)" -match 'Loopback') { continue }
        [void]$net.Add([ordered]@{ iface = "$($n.Name)"; rx_bytes = [int64]$n.BytesReceivedPersec; rx_pkts = [int64]$n.PacketsReceivedPersec; tx_bytes = [int64]$n.BytesSentPersec; tx_pkts = [int64]$n.PacketsSentPersec })
    }
}

# ---- Connessioni TCP (una lettura, riusata da conns/flows/listening) ----
$tcp = @()
try { $tcp = @(Get-NetTCPConnection -ErrorAction Stop) } catch { }
$estabConn = @($tcp | Where-Object { $_.State -eq 'Established' })
$listenConn = @($tcp | Where-Object { $_.State -eq 'Listen' })
$conns = [ordered]@{ total = $tcp.Count; estab = $estabConn.Count }

# ---- FLUSSI: connessioni ESTABLISHED aggregate per (IP remoto, porta di servizio) ----
$listenPorts = @{}
foreach ($c in $listenConn) { $listenPorts[[int]$c.LocalPort] = $true }
$inbound = @{}; $outbound = @{}
foreach ($c in $estabConn) {
    $rip = "$($c.RemoteAddress)"; $rport = [int]$c.RemotePort; $lport = [int]$c.LocalPort
    if ([string]::IsNullOrEmpty($rip) -or $rip -in @('127.0.0.1', '::1', '0.0.0.0', '::')) { continue }
    if ($listenPorts.ContainsKey($lport)) { $k = "$rip|$lport"; if ($inbound.ContainsKey($k)) { $inbound[$k]++ } else { $inbound[$k] = 1 } }
    else { $k = "$rip|$rport"; if ($outbound.ContainsKey($k)) { $outbound[$k]++ } else { $outbound[$k] = 1 } }
}
function TopFlows($h, $cap) {
    $arr = New-Object System.Collections.ArrayList
    foreach ($kv in ($h.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $cap)) {
        $parts = $kv.Key -split '\|', 2
        [void]$arr.Add([ordered]@{ ip = $parts[0]; port = [int]$parts[1]; n = $kv.Value })
    }
    return , $arr
}
$flows = [ordered]@{ in = (TopFlows $inbound 40); out = (TopFlows $outbound 40); in_peers = $inbound.Count; out_peers = $outbound.Count }

# ---- DOCKER (se il CLI è presente; stessi comandi/formato della sonda Linux) ----
$docker = $null; $docker_images = $null
if (Have 'docker') {
    $states = @{}
    foreach ($line in @(& docker ps -a --format "{{.Names}}`t{{.State}}`t{{.Status}}" 2>$null)) {
        $p = "$line" -split "`t"
        if ($p.Count -lt 2) { continue }
        $health = ''; $status = if ($p.Count -gt 2) { $p[2] } else { '' }
        if ($status -match '\((healthy|unhealthy|health: starting|starting)\)') { $health = $Matches[1] }
        $states[$p[0]] = [ordered]@{ state = $p[1]; health = $health }
    }
    $live = @{}
    foreach ($line in @(& docker stats --no-stream --format "{{.Name}}`t{{.CPUPerc}}`t{{.MemUsage}}`t{{.MemPerc}}`t{{.NetIO}}`t{{.BlockIO}}`t{{.PIDs}}" 2>$null)) {
        $p = "$line" -split "`t"
        if ($p.Count -lt 7) { continue }
        $live[$p[0]] = [ordered]@{ cpu_pct = (ToPct $p[1]); mem_usage = $p[2]; mem_pct = (ToPct $p[3]); net_io = $p[4]; blk_io = $p[5]; pids = (ToInt $p[6]) }
    }
    $dl = New-Object System.Collections.ArrayList
    foreach ($name in ($states.Keys | Sort-Object)) {
        $row = [ordered]@{ name = $name }
        foreach ($e in $states[$name].GetEnumerator()) { $row[$e.Key] = $e.Value }
        $lv = if ($live.ContainsKey($name)) { $live[$name] } else { [ordered]@{ cpu_pct = $null; mem_usage = $null; mem_pct = $null; net_io = $null; blk_io = $null; pids = $null } }
        foreach ($e in $lv.GetEnumerator()) { $row[$e.Key] = $e.Value }
        [void]$dl.Add($row)
    }
    $docker = $dl
    $ids = @(& docker images -q 2>$null | Where-Object { "$_".Trim() -ne '' })
    $docker_images = @($ids | Sort-Object -Unique).Count
}

# ---- SICUREZZA ----
# firewall/fail2ban: nessun contatore cumulativo affidabile su Windows -> null.
# SSH: Event Log Security 4625 (logon falliti) nell'ultima ora; "invalid user" ~ SubStatus 0xC0000064.
$sec = [ordered]@{ fw_dropped_pkts = $null; ssh_failed_1h = $null; ssh_invalid_1h = $null; f2b_banned = $null; f2b_total_failed = $null; listening = $null }
try {
    $since = (Get-Date).AddHours(-1)
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction Stop)
    $sec.ssh_failed_1h = $ev.Count
    $sec.ssh_invalid_1h = @($ev | Where-Object { "$($_.Message)" -match '0xC0000064' }).Count
} catch {
    # "No events found" = accessibile ma nessun evento (0); altro errore = non accessibile (null)
    if ("$($_.Exception.Message)" -match 'No events') { $sec.ssh_failed_1h = 0; $sec.ssh_invalid_1h = 0 }
}
$listenList = New-Object System.Collections.ArrayList
foreach ($c in $listenConn) { [void]$listenList.Add([ordered]@{ proto = 'tcp'; addr = "$($c.LocalAddress)"; port = "$($c.LocalPort)" }) }
foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) { if ($u) { [void]$listenList.Add([ordered]@{ proto = 'udp'; addr = "$($u.LocalAddress)"; port = "$($u.LocalPort)" }) } }
$sec.listening = $listenList

# ---- documento finale (schema identico a Linux/macOS) ----
$doc = [ordered]@{
    v = $PROBE_VERSION
    host = "$env:COMPUTERNAME"
    ts = [int64](Get-Date -UFormat %s)
    cpus = $cpus
    ram = $ram
    disk = $disk
    net = $net
    conns = $conns
    flows = $flows
    docker = $docker
    docker_images = $docker_images
    security = $sec
}
$doc | ConvertTo-Json -Depth 8 -Compress
