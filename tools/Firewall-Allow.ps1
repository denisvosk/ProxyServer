#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string] $InstallDirectory = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('Domain', 'Private', 'Public')]
    [ValidateNotNullOrEmpty()]
    [string[]] $Profile = @('Domain', 'Private', 'Public'),
    [switch] $IncludeMTProto
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Firewall-Common.ps1')
Import-Module NetSecurity -ErrorAction Stop
$plan = Get-ProxyFirewallPlan $InstallDirectory $Profile -IncludeMTProto:$IncludeMTProto
Write-Host "Installation: $($plan.Root)"
Write-Host "Rule group:   $($plan.Group)"
Write-Host 'Only the following program/port allow rules can be added:'
$plan.Rules | Select-Object Program, Protocol, @{n='LocalPort';e={$_.Ports -join ','}}, LocalAddress, RemoteAddress, @{n='Profile';e={$_.Profiles -join ','}} | Format-List | Out-Host

# Preflight every existing rule before the first write. Old rules are never
# silently replaced or removed by this additive script.
$allRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
$existing = @($allRules | Where-Object { $_.Group -ceq $plan.Group })
foreach ($spec in $plan.Rules) {
    $same = @($allRules | Where-Object { $_.Name -ceq $spec.Name })
    if ($same.Count -gt 1) { throw 'Duplicate firewall rule names found; no changes were made.' }
    if ($same.Count -eq 1) { Assert-ProxyExistingRule $same[0] $spec }
}
$plannedNames = @($plan.Rules | ForEach-Object { $_.Name })
if (@($existing | Where-Object { $_.Name -notin $plannedNames }).Count -gt 0) {
    Write-Warning 'This installation has rules from an earlier configuration. They remain unchanged. Review them; Firewall-Undo.ps1 removes only this helper''s own rules before a fresh apply.'
}
foreach ($spec in $plan.Rules) {
    if (@($existing | Where-Object { $_.Name -ceq $spec.Name }).Count -eq 1) { Write-Host "Already matches: $($spec.Name)"; continue }
    if ($PSCmdlet.ShouldProcess($spec.Program + ' ' + $spec.Protocol + ' ' + ($spec.Ports -join ','), 'Add this inbound allow rule')) {
        New-NetFirewallRule -Name $spec.Name -DisplayName $spec.DisplayName -Description $spec.Description -Group $spec.Group `
            -PolicyStore PersistentStore -Direction Inbound -Action Allow -Enabled True -Profile $spec.Profiles `
            -Program $spec.Program -Protocol $spec.Protocol -LocalPort $spec.Ports -RemotePort Any `
            -LocalAddress $spec.LocalAddress -RemoteAddress $spec.RemoteAddress -EdgeTraversalPolicy Block `
            -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "Added: $($spec.Name)"
    }
}
Write-Host 'Finished. This script does not change firewall profiles, default policies, RDP, routes, services, or any pre-existing rule.'
if ($plan.Rules.Count -eq 0) { Write-Host 'No external listeners require rules in the saved configuration.' }
