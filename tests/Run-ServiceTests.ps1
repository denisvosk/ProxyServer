#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $BuildDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'build/windows-service-tests'),
    [string] $GuiExecutable = (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/x64/Release/ProxyServer.exe')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:ENABLE_PROXY_SERVICE_TESTS -ne '1') {
    throw 'This integration test installs its own temporary service and is limited to an explicitly opted-in disposable GitHub-hosted Windows runner.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The Windows runner is not elevated; no SCM test was performed.' }
if (Get-Service -Name 'ProxyServer21' -ErrorAction SilentlyContinue) { throw 'Refusing to touch a pre-existing ProxyServer21 service.' }
foreach ($path in @((Join-Path $env:ProgramData 'ProxyServer21'), (Join-Path $env:ProgramFiles 'ProxyServer21'))) {
    if (Test-Path -LiteralPath $path) { throw "Refusing to touch pre-existing application data: $path" }
}
$root = Split-Path -Parent $PSScriptRoot
$GuiExecutable = (Get-Item -LiteralPath $GuiExecutable -ErrorAction Stop).FullName
& cmake -S (Join-Path $PSScriptRoot 'windows') -B $BuildDirectory -G 'Visual Studio 17 2022' -A x64
if ($LASTEXITCODE -ne 0) { throw 'Windows test project configuration failed.' }
& cmake --build $BuildDirectory --config Release --parallel 2
if ($LASTEXITCODE -ne 0) { throw 'Windows test project compilation failed.' }
& ctest --test-dir $BuildDirectory -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'Windows portable unit tests failed.' }
$env:PROXY_GUI_EXE = $GuiExecutable
$env:PROXY_UI_SCREENSHOT = Join-Path $root 'windows-service-ui.png'
$test = Join-Path $BuildDirectory 'Release/service_integration_win.exe'
$log = Join-Path $root 'windows-service-integration.log'
& $test 2>&1 | Tee-Object -FilePath $log
if ($LASTEXITCODE -ne 0) { throw "SCM integration failed; see $log" }
if (-not (Select-String -LiteralPath $log -SimpleMatch 'WINDOWS_SERVICE_INTEGRATION_PASSED' -Quiet)) { throw 'SCM integration did not print its explicit completion marker.' }
Write-Host 'Windows SCM, scoped firewall COM rules, real GUI close, GOST loopback traffic, recovery, persistence, and uninstall checks passed.'
