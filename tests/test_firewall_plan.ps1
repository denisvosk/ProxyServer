# Portable parser/plan tests. No firewall module is imported and no firewall
# command is executed. The optional administrator scripts are parsed only.
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = Split-Path -Parent $PSScriptRoot
. (Join-Path $project 'tools/Firewall-Common.ps1')
$script:planChecks = 0
function Assert-Plan([bool] $Condition, [string] $Message) { if (-not $Condition) { throw $Message }; $script:planChecks++ }
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('proxy-firewall-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory((Join-Path $testRoot 'components')) | Out-Null
[IO.File]::WriteAllText((Join-Path $testRoot 'components/gost.exe'), 'inert fixture, not executable')
[IO.File]::WriteAllText((Join-Path $testRoot 'components/mtg.exe'), 'inert fixture, not executable')
$iniPath = Join-Path $testRoot 'proxy.ini'
$fixture = @'
[proxy]
version=2
user_utf8_hex=746573742d6f6e6c79
password_dpapi=test-only
bind_address=0.0.0.0
allow_ip=198.51.100.9
enable_socks=1
socks_port=1080
enable_http=1
http_port=8080
enable_chain_socks=0
chain_socks_port=1081
enable_chain_http=0
chain_http_port=8081
enable_https=0
https_port=8443
enable_socks_tls=0
socks_tls_port=1443
enable_dns=1
dns_port=1053
enable_socks_udp=1
udp_port_min=20000
udp_port_max=20100
tls_use_chain=0
upstream_type=socks5
[mtproto]
bind_address=0.0.0.0
port=443
secret_dpapi=test-only
autostart=0
'@
function Save-Fixture([string] $Text) { [IO.File]::WriteAllText($iniPath, $Text, [Text.Encoding]::Unicode) }
function Assert-Rejected([string] $Text, [string] $Reason) {
    Save-Fixture $Text
    $rejected = $false
    try { Get-ProxyFirewallPlan $testRoot @('Public') | Out-Null } catch { $rejected = $true }
    Assert-Plan $rejected "Accepted invalid configuration: $Reason"
}
try {
    Save-Fixture $fixture
    $plan = Get-ProxyFirewallPlan $testRoot @('Public')
    Assert-Plan ($plan.Rules.Count -eq 2) 'Expected GOST TCP and UDP only.'
    Assert-Plan ($plan.Rules[0].Program.EndsWith('gost.exe')) 'Wrong program scope.'
    Assert-Plan (Test-ProxySameSet $plan.Rules[0].Ports @('1080','8080')) 'Wrong enabled TCP port set or external DNS rule.'
    Assert-Plan ($plan.Rules[1].Ports[0] -eq '20000-20100') 'Wrong UDP range.'
    Assert-Plan ($plan.Rules[0].RemoteAddress -eq '198.51.100.9' -and $plan.Rules[1].RemoteAddress -eq '198.51.100.9') 'Source IP restriction was lost.'
    Assert-Plan ($plan.Rules[0].ProfileMask -eq 4) 'Wrong firewall profile.'
    $same = Get-ProxyFirewallPlan $testRoot @('Public')
    Assert-Plan ($same.Rules[0].Name -ceq $plan.Rules[0].Name) 'Rule identity is not deterministic.'
    $mt = Get-ProxyFirewallPlan $testRoot @('Public') -IncludeMTProto
    Assert-Plan ($mt.Rules.Count -eq 3 -and $mt.Rules[2].Program.EndsWith('mtg.exe') -and $mt.Rules[2].Ports[0] -eq '443') 'Explicit MTProto inclusion failed.'
    Assert-Plan ($mt.Rules[2].RemoteAddress -eq 'Any') 'GOST allow_ip leaked into MTProto.'
    Save-Fixture ($fixture.Replace('bind_address=0.0.0.0','bind_address=127.0.0.1'))
    $loopback = Get-ProxyFirewallPlan $testRoot @('Public') -IncludeMTProto
    Assert-Plan ($loopback.Rules.Count -eq 0) 'Loopback-only listeners received external rules.'
    Save-Fixture ($fixture.Replace('enable_socks=1','enable_socks=0').Replace('enable_http=1','enable_http=0').Replace('enable_chain_socks=0','enable_chain_socks=1').Replace('upstream_type=socks5','upstream_type=http'))
    $httpChain = Get-ProxyFirewallPlan $testRoot @('Domain','Private','Public')
    Assert-Plan ($httpChain.Rules.Count -eq 1 -and $httpChain.Rules[0].Protocol -eq 'TCP' -and $httpChain.Rules[0].Ports[0] -eq '1081') 'HTTP upstream chain incorrectly opened UDP.'
    Assert-Plan ($httpChain.Rules[0].ProfileMask -eq 7) 'All-profile selection failed.'
    Assert-Rejected ($fixture.Replace('socks_port=1080','socks_port=65536')) 'oversized port'
    Assert-Rejected ($fixture.Replace('socks_port=1080','socks_port=0')) 'zero port'
    Assert-Rejected ($fixture.Replace('socks_port=1080','socks_port=8080')) 'duplicate enabled port'
    Assert-Rejected ($fixture.Replace('enable_http=1','enable_http=true')) 'ambiguous boolean'
    Assert-Rejected ($fixture.Replace('version=2','version=1')) 'old schema'
    Assert-Rejected ($fixture.Replace('udp_port_min=20000','udp_port_min=20200')) 'reversed UDP range'
    Assert-Rejected ($fixture.Replace('udp_port_min=20000','udp_port_min=1053')) 'UDP/DNS overlap'
    Assert-Rejected ($fixture.Replace('allow_ip=198.51.100.9','allow_ip=198.51.100.0/24')) 'subnet instead of exact client IP'
    Assert-Rejected ($fixture.Replace('bind_address=0.0.0.0','bind_address=0.0.0.0/0')) 'network instead of bind IP'
    Assert-Rejected ($fixture + "`n[proxy]`nversion=2") 'duplicate section'
    Assert-Rejected ($fixture.Replace('enable_http=1',"enable_http=1`nenable_http=0")) 'duplicate key'
    Assert-Rejected ($fixture.Replace('enable_http=1', '')) 'missing enable flag'
    Assert-Rejected ($fixture.Replace('password_dpapi=test-only','password_dpapi=')) 'missing saved password'
    Assert-Rejected ($fixture.Replace('user_utf8_hex=746573742d6f6e6c79','user_utf8_hex=123')) 'odd-length username hex'
    Assert-Rejected ($fixture.Replace('user_utf8_hex=746573742d6f6e6c79','user_utf8_hex=ff')) 'invalid UTF-8 username'
    Assert-Rejected ($fixture.Replace('user_utf8_hex=746573742d6f6e6c79','user_utf8_hex=')) 'empty encoded username'
    Save-Fixture ($fixture.Replace('user_utf8_hex=746573742d6f6e6c79','user=test-only'))
    $legacy = Get-ProxyFirewallPlan $testRoot @('Public')
    Assert-Plan ($legacy.Rules.Count -eq 2) 'Legacy plain username fallback failed.'
    Save-Fixture $fixture
    $rejected = $false
    try { Get-ProxyFirewallPlan $testRoot @() | Out-Null } catch { $rejected = $true }
    Assert-Plan $rejected 'Accepted an empty profile selection.'
    foreach ($name in @('Firewall-Allow.ps1','Firewall-Undo.ps1','Firewall-Common.ps1')) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $project ('tools/' + $name)), [ref]$tokens, [ref]$errors)
        Assert-Plan ($errors.Count -eq 0) ("PowerShell syntax error: " + $name)
        if ($name -ne 'Firewall-Common.ps1') {
            Assert-Plan $ast.ScriptRequirements.IsElevationRequired 'Administrator requirement is absent.'
            $checks = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'ShouldProcess' }, $true))
            Assert-Plan ($checks.Count -gt 0) 'No ShouldProcess guard for WhatIf/Confirm.'
        }
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($command in $commands) {
            Assert-Plan ($command -notmatch '^(Set|Disable|Enable|Reset)-NetFirewall|^netsh$|^Set-Service$|^Restart-Service$|^New-NetRoute$|^Remove-NetRoute$') 'Forbidden broad network/firewall mutation found.'
        }
    }
    Write-Host "PASS: $script:planChecks firewall script syntax, elevation/ShouldProcess, configuration and plan assertions. No firewall commands were executed."
} finally {
    # Only our newly generated, uniquely named inert test directory is removed.
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
