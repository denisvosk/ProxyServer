# Pure configuration/planning helpers. This file never changes firewall rules.
Set-StrictMode -Version Latest

function Get-ProxyHash([string] $Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-ProxyInstallIdentity([string] $InstallDirectory) {
    $item = Get-Item -LiteralPath $InstallDirectory -ErrorAction Stop
    if (-not $item.PSIsContainer) { throw 'InstallDirectory must be the extracted ProxyServer directory.' }
    $root = [IO.Path]::GetFullPath($item.FullName)
    $id = (Get-ProxyHash $root.TrimEnd([char[]]'\/').ToLowerInvariant()).Substring(0, 16)
    return [pscustomobject]@{ Root = $root; Group = "ProxyServer.2.0.$id" }
}

function Read-ProxyIni([string] $Path) {
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 262144) { throw 'Invalid or oversized proxy.ini.' }
    $sections = @{}
    $current = $null
    $lineNumber = 0
    # ReadAllLines detects the UTF-16 BOM written by the Windows application.
    foreach ($raw in [IO.File]::ReadAllLines($file.FullName)) {
        $lineNumber++
        $line = $raw.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith(';') -or $line.StartsWith('#')) { continue }
        if ($line -match '^\[([a-zA-Z0-9_-]+)\]$') {
            $name = $Matches[1].ToLowerInvariant()
            if ($sections.ContainsKey($name)) { throw "Duplicate INI section on line $lineNumber." }
            $current = @{}
            $sections[$name] = $current
            continue
        }
        $index = $line.IndexOf('=')
        if ($null -eq $current -or $index -lt 1) { throw "Invalid INI syntax on line $lineNumber." }
        $key = $line.Substring(0, $index).Trim().ToLowerInvariant()
        if ($key -notmatch '^[a-z0-9_]+$' -or $current.ContainsKey($key)) { throw "Invalid or duplicate INI key on line $lineNumber." }
        $current[$key] = $line.Substring($index + 1).Trim()
    }
    return $sections
}

function Get-ProxyValue([hashtable] $Section, [string] $Key) {
    if (-not $Section.ContainsKey($Key)) { throw "Missing '$Key'. Save settings in this release before running the firewall helper." }
    return [string]$Section[$Key]
}

function Get-ProxyBoolean([hashtable] $Section, [string] $Key) {
    $value = Get-ProxyValue $Section $Key
    if ($value -ne '0' -and $value -ne '1') { throw "'$Key' must be exactly 0 or 1." }
    return $value -eq '1'
}

function Get-ProxySavedUsername([hashtable] $Section) {
    if ($Section.ContainsKey('user_utf8_hex')) {
        $hex = [string]$Section['user_utf8_hex']
        if ($hex -notmatch '^(?:[0-9a-fA-F]{2}){1,255}$') { throw 'Invalid saved username encoding. Save the main settings again.' }
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($index = 0; $index -lt $bytes.Length; $index++) { $bytes[$index] = [Convert]::ToByte($hex.Substring($index * 2, 2), 16) }
        $utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false, $true
        try { return $utf8.GetString($bytes) } catch { throw 'Invalid UTF-8 saved username. Save the main settings again.' }
    }
    return Get-ProxyValue $Section 'user'
}

function Get-ProxyPort([hashtable] $Section, [string] $Key) {
    $value = Get-ProxyValue $Section $Key
    $number = 0
    if ($value -notmatch '^[0-9]{1,5}$' -or -not [int]::TryParse($value, [ref]$number) -or $number -lt 1 -or $number -gt 65535) {
        throw "'$Key' must be a port from 1 to 65535."
    }
    return $number
}

function Get-ProxyIPv4([string] $Value, [string] $Field, [switch] $AllowAny) {
    if ($Value -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$') { throw "'$Field' must be one exact IPv4 address." }
    foreach ($octet in $Value.Split('.')) { if ([int]$octet -gt 255) { throw "'$Field' contains an invalid IPv4 octet." } }
    if ($Value -eq '0.0.0.0' -and -not $AllowAny) { throw "'$Field' cannot be 0.0.0.0." }
    if ([int]$Value.Split('.')[0] -ge 224) { throw "'$Field' cannot be a multicast or reserved address." }
    return $Value
}

function New-ProxyRuleSpec($Identity, [string] $Engine, [string] $Protocol, [string[]] $Ports, [string] $LocalAddress, [string] $RemoteAddress, [string[]] $Profiles) {
    $program = Join-Path $Identity.Root "components\$Engine.exe"
    $file = Get-Item -LiteralPath $program -ErrorAction Stop
    if ($file.PSIsContainer) { throw "Missing bundled component $Engine.exe." }
    $profileSet = @($Profiles | Sort-Object -Unique)
    $portSet = @($Ports | Sort-Object -Unique)
    $hash = (Get-ProxyHash ($Engine + '|' + $Protocol + '|' + ($portSet -join ',') + '|' + $LocalAddress + '|' + $RemoteAddress + '|' + ($profileSet -join ','))).Substring(0, 16)
    $mask = 0
    foreach ($profile in $profileSet) { switch ($profile) { 'Domain' { $mask = $mask -bor 1 }; 'Private' { $mask = $mask -bor 2 }; 'Public' { $mask = $mask -bor 4 }; default { throw 'Invalid firewall profile.' } } }
    return [pscustomobject]@{
        Name = $Identity.Group + '.' + $Engine + '.' + $Protocol.ToLowerInvariant() + '.' + $hash
        Group = $Identity.Group
        DisplayName = "Proxy Server 2.0 - $Engine $Protocol ($($portSet -join ','))"
        Description = "Managed by ProxyServer 2.0 optional firewall helper; install=$($Identity.Root); plan=$hash"
        Program = $file.FullName
        Protocol = $Protocol
        Ports = $portSet
        LocalAddress = $LocalAddress
        RemoteAddress = $RemoteAddress
        Profiles = $profileSet
        ProfileMask = $mask
    }
}

function Get-ProxyFirewallPlan([string] $InstallDirectory, [string[]] $Profiles, [switch] $IncludeMTProto) {
    if ($null -eq $Profiles -or $Profiles.Count -eq 0) { throw 'Select at least one firewall profile.' }
    $identity = Get-ProxyInstallIdentity $InstallDirectory
    $ini = Read-ProxyIni (Join-Path $identity.Root 'proxy.ini')
    if (-not $ini.ContainsKey('proxy')) { throw 'Missing [proxy] section. Save the main settings first.' }
    $p = $ini['proxy']
    if ((Get-ProxyValue $p 'version') -ne '2') { throw 'This helper requires settings saved by Proxy Server 2.0.' }
    if ([string]::IsNullOrWhiteSpace((Get-ProxySavedUsername $p)) -or [string]::IsNullOrWhiteSpace((Get-ProxyValue $p 'password_dpapi'))) { throw 'Save a nonempty local username and password first.' }
    $bind = Get-ProxyIPv4 (Get-ProxyValue $p 'bind_address') 'bind_address' -AllowAny
    $local = if ($bind -eq '0.0.0.0') { 'Any' } else { $bind }
    $allow = Get-ProxyValue $p 'allow_ip'
    $remote = if ($allow.Length -eq 0) { 'Any' } else { Get-ProxyIPv4 $allow 'allow_ip' }
    $rules = New-Object 'System.Collections.Generic.List[object]'
    $ports = New-Object 'System.Collections.Generic.List[string]'
    $used = @{}
    $enabled = @{}
    foreach ($entry in @(
        @('enable_socks', 'socks_port'), @('enable_http', 'http_port'),
        @('enable_chain_socks', 'chain_socks_port'), @('enable_chain_http', 'chain_http_port'),
        @('enable_https', 'https_port'), @('enable_socks_tls', 'socks_tls_port'), @('enable_dns', 'dns_port')
    )) {
        $on = Get-ProxyBoolean $p $entry[0]
        $port = Get-ProxyPort $p $entry[1]
        $enabled[$entry[0]] = $on
        if ($on) {
            if ($used.ContainsKey($port)) { throw "Enabled listeners share port $port. Save a consistent configuration first." }
            $used[$port] = $true
            # DNS is deliberately bound to 127.0.0.1; it gets no inbound rule.
            if ($entry[0] -ne 'enable_dns') { $ports.Add([string]$port) }
        }
    }
    $udp = Get-ProxyBoolean $p 'enable_socks_udp'
    $tlsChain = Get-ProxyBoolean $p 'tls_use_chain'
    $upstream = Get-ProxyValue $p 'upstream_type'
    if ($upstream -ne 'socks5' -and $upstream -ne 'http') { throw 'Invalid upstream_type.' }
    $low = Get-ProxyPort $p 'udp_port_min'
    $high = Get-ProxyPort $p 'udp_port_max'
    if ($low -gt $high) { throw 'udp_port_min must not exceed udp_port_max.' }
    if ($udp -and $enabled['enable_dns']) {
        $dns = Get-ProxyPort $p 'dns_port'
        if ($dns -ge $low -and $dns -le $high) { throw 'The UDP relay range overlaps the local DNS listener.' }
    }
    $supportsUDP = $enabled['enable_socks'] -or ($enabled['enable_chain_socks'] -and $upstream -eq 'socks5') -or ($enabled['enable_socks_tls'] -and (-not $tlsChain -or $upstream -eq 'socks5'))
    if ($ports.Count -gt 0 -and -not $bind.StartsWith('127.')) {
        $rules.Add((New-ProxyRuleSpec $identity 'gost' 'TCP' $ports.ToArray() $local $remote $Profiles))
        if ($udp -and $supportsUDP) { $rules.Add((New-ProxyRuleSpec $identity 'gost' 'UDP' @("$low-$high") $local $remote $Profiles)) }
    }
    if ($IncludeMTProto) {
        if (-not $ini.ContainsKey('mtproto')) { throw 'No saved MTProto configuration. Save the Telegram page first.' }
        $mt = $ini['mtproto']
        if ([string]::IsNullOrWhiteSpace((Get-ProxyValue $mt 'secret_dpapi'))) { throw 'Save an MTProto secret first.' }
        $mtPort = Get-ProxyPort $mt 'port'
        $mtBind = Get-ProxyIPv4 (Get-ProxyValue $mt 'bind_address') 'mtproto.bind_address' -AllowAny
        if ($used.ContainsKey($mtPort)) { throw 'The MTProto port conflicts with an enabled proxy listener.' }
        if (-not $mtBind.StartsWith('127.')) {
            $mtLocal = if ($mtBind -eq '0.0.0.0') { 'Any' } else { $mtBind }
            # allow_ip is a GOST setting and must not silently restrict MTProto.
            $rules.Add((New-ProxyRuleSpec $identity 'mtg' 'TCP' @([string]$mtPort) $mtLocal 'Any' $Profiles))
        }
    }
    return [pscustomobject]@{ Root = $identity.Root; Group = $identity.Group; Rules = $rules.ToArray() }
}

function Test-ProxySameSet($Left, $Right) {
    return ((@($Left | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique) -join '|') -ceq (@($Right | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique) -join '|'))
}

function Assert-ProxyExistingRule($Existing, $Spec) {
    $application = $Existing | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $port = $Existing | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $Existing | Get-NetFirewallAddressFilter -ErrorAction Stop
    $protocolNumber = if ($Spec.Protocol -eq 'TCP') { '6' } else { '17' }
    $matches = $Existing.Group -ceq $Spec.Group -and $Existing.Description -ieq $Spec.Description -and
        [string]$Existing.Direction -eq 'Inbound' -and [string]$Existing.Action -eq 'Allow' -and
        [string]$Existing.Enabled -eq 'True' -and [int]$Existing.Profile -eq $Spec.ProfileMask -and
        [string]$Existing.EdgeTraversalPolicy -eq 'Block' -and $application.Program -ieq $Spec.Program -and
        ([string]$port.Protocol -eq $Spec.Protocol -or [string]$port.Protocol -eq $protocolNumber) -and
        (Test-ProxySameSet $port.LocalPort $Spec.Ports) -and (Test-ProxySameSet $port.RemotePort @('Any')) -and
        (Test-ProxySameSet $address.LocalAddress @($Spec.LocalAddress)) -and (Test-ProxySameSet $address.RemoteAddress @($Spec.RemoteAddress))
    if (-not $matches) { throw "Existing rule '$($Spec.Name)' differs from this exact plan. Nothing was changed; review it or use Firewall-Undo.ps1 for this installation." }
}
