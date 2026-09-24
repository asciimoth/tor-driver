[CmdletBinding()]
param(
    [string]$ArtifactDir = (Join-Path $PWD '.artifacts-windows-containment'),
    [Parameter(Mandatory)] [string]$IPv4Probe,
    [Parameter(Mandatory)] [string]$IPv6Probe,
    [Parameter(Mandatory)] [string]$UDPProbe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:CGO_ENABLED = '0'
$env:GOTOOLCHAIN = 'local'
$env:TOR_DRIVER_WINDOWS_CONTAINMENT = '1'
$env:TOR_DRIVER_WINDOWS_PROBE_IPV4 = $IPv4Probe
$env:TOR_DRIVER_WINDOWS_PROBE_IPV6 = $IPv6Probe
$env:TOR_DRIVER_WINDOWS_PROBE_UDP = $UDPProbe

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem) {
    throw 'The Windows containment gate must run as SYSTEM through QEMU Guest Agent'
}
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
$eventsPath = Join-Path $ArtifactDir 'containment-test-events.jsonl'
$readablePath = Join-Path $ArtifactDir 'containment-test.log'

& go test -json -count=1 -run '^TestWindowsContainedSystemEnforcesNetworkBoundary$' -timeout 2m ./direct |
    Tee-Object -FilePath $eventsPath
$testExit = $LASTEXITCODE
$events = @(Get-Content -LiteralPath $eventsPath | ForEach-Object {
    if ($_ -match '^\s*\{') { $_ | ConvertFrom-Json }
})
$events | Where-Object Action -eq 'output' | ForEach-Object Output |
    Set-Content -LiteralPath $readablePath
if ($testExit -ne 0) {
    throw "Windows containment test failed with exit code $testExit"
}
$testName = 'TestWindowsContainedSystemEnforcesNetworkBoundary'
if ($events | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $testName -and $_.Action -eq 'skip' }) {
    throw "$testName was skipped"
}
if (-not ($events | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $testName -and $_.Action -eq 'pass' })) {
    throw "$testName has no structured pass event"
}
