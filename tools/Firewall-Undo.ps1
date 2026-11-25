#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([string] $InstallDirectory = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Firewall-Common.ps1')
Import-Module NetSecurity -ErrorAction Stop
$identity = Get-ProxyInstallIdentity $InstallDirectory
$pattern = '^' + [regex]::Escape($identity.Group) + '\.(gost|mtg)\.(tcp|udp)\.[0-9a-f]{16}$'
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {
    $_.Group -ceq $identity.Group -and $_.Name -cmatch $pattern -and
    $null -ne $_.Description -and
    $_.Description.StartsWith('Managed by ProxyServer 2.0 optional firewall helper; install=' + $identity.Root + '; plan=', [StringComparison]::OrdinalIgnoreCase)
})
Write-Host "Installation: $($identity.Root)"
Write-Host "Exact group:  $($identity.Group)"
$rules | Select-Object Name, DisplayName, Group | Format-Table -AutoSize | Out-Host
foreach ($rule in $rules) {
    if ($PSCmdlet.ShouldProcess($rule.Name, 'Remove this ProxyServer helper rule')) {
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -Confirm:$false -ErrorAction Stop
        Write-Host "Removed: $($rule.Name)"
    }
}
Write-Host 'Finished. Only matching rules created by this helper for this exact installation were eligible. Other firewall rules and settings are unchanged.'
