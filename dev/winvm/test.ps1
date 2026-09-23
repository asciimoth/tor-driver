[CmdletBinding()]
param(
    [string]$ArtifactDir = (Join-Path $PWD '.artifacts-windows'),
    [string]$ImageManifest = $env:WINVM_IMAGE_MANIFEST,
    [string]$ExpectedGoVersion = $env:GO_EXPECTED_VERSION,
    [string]$ExpectedTorVersion = $env:TOR_EXPECTED_VERSION,
    [switch]$PublicOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:CGO_ENABLED = '0'
$env:GOTOOLCHAIN = 'local'

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
$transcript = Join-Path $ArtifactDir 'powershell.log'
Start-Transcript -Path $transcript -Force | Out-Null

function Invoke-Logged {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Command,
        [Parameter(Mandatory)] [string[]]$Arguments
    )
    Write-Host "==> $Name"
    $logPath = Join-Path $ArtifactDir "$Name.log"
    New-Item -ItemType File -Force -Path $logPath | Out-Null
    & $Command @Arguments | Tee-Object -FilePath $logPath
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Name failed with exit code $exitCode"
    }
}

function Assert-RequiredTestEvents {
    param(
        [Parameter(Mandatory)] [string]$EventsPath,
        [Parameter(Mandatory)] [string]$ReadablePath,
        [Parameter(Mandatory)] [string[]]$RequiredTests
    )
    $events = @(Get-Content -LiteralPath $EventsPath | ForEach-Object {
        if ($_ -match '^\s*\{') { $_ | ConvertFrom-Json }
    })
    $events | Where-Object Action -eq 'output' | ForEach-Object Output |
        Set-Content -LiteralPath $ReadablePath
    foreach ($testName in $RequiredTests) {
        if ($events | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $testName -and $_.Action -eq 'skip' }) {
            throw "$testName was skipped"
        }
        if (-not ($events | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $testName -and $_.Action -eq 'pass' })) {
            throw "$testName has no structured pass event"
        }
    }
}

try {
    if ($ImageManifest) {
        if (-not (Test-Path -LiteralPath $ImageManifest -PathType Leaf)) {
            throw "Windows image manifest is absent: $ImageManifest"
        }
        $manifest = Get-Content -LiteralPath $ImageManifest -Raw | ConvertFrom-Json
        if (-not $ExpectedTorVersion) {
            $ExpectedTorVersion = $manifest.torVersion
        }
        if (-not $ExpectedGoVersion) {
            if ($manifest.goVersion -notmatch '^go version go(?<Version>\S+) windows/amd64$') {
                throw 'The image manifest has no valid Go version'
            }
            $ExpectedGoVersion = $Matches['Version']
        }
        if (-not $env:TOR_BINARY -and $manifest.torBinary) {
            $env:TOR_BINARY = $manifest.torBinary
        }
    }
    if (-not $env:TOR_BINARY) {
        throw 'TOR_BINARY is not set'
    }
    if (-not (Test-Path -LiteralPath $env:TOR_BINARY -PathType Leaf)) {
        throw "Tor executable is absent: $env:TOR_BINARY"
    }
    if (-not $ExpectedTorVersion) {
        throw 'The expected Tor version is not set'
    }
    if (-not $ExpectedGoVersion) {
        throw 'The expected Go version is not set'
    }
    $actualGoVersion = (& go env GOVERSION | Out-String).Trim()
    $goVersionExit = $LASTEXITCODE
    if ($goVersionExit -ne 0) {
        throw "Go version check failed with exit code $goVersionExit"
    }
    if ($actualGoVersion -ne "go$ExpectedGoVersion") {
        throw "Go version is $actualGoVersion, not go$ExpectedGoVersion"
    }
    $torOutput = (& $env:TOR_BINARY --version | Out-String).Trim()
    $torExit = $LASTEXITCODE
    $torOutput | Tee-Object -FilePath (Join-Path $ArtifactDir 'tor-version.log') | Write-Host
    if ($torExit -ne 0) {
        throw "Tor version check failed with exit code $torExit"
    }
    if ($torOutput -notmatch "(?m)^Tor version $([regex]::Escape($ExpectedTorVersion))\b") {
        throw "Tor version does not match $ExpectedTorVersion"
    }

    if ($PublicOnly) {
        $env:TOR_DRIVER_LIVE = '1'
        $eventsPath = Join-Path $ArtifactDir 'public-test-events.jsonl'
        & go test -json -count=1 -tags=e2e -run '^TestTorOnionHTTPAndOutboundReplacement$' -v -timeout 15m . |
            Tee-Object -FilePath $eventsPath
        $testExit = $LASTEXITCODE
        if ($testExit -ne 0) {
            throw "public test failed with exit code $testExit"
        }
        Assert-RequiredTestEvents `
            -EventsPath $eventsPath `
            -ReadablePath (Join-Path $ArtifactDir 'public-test.log') `
            -RequiredTests @('TestTorOnionHTTPAndOutboundReplacement')
        exit 0
    }

    Invoke-Logged 'go-version' 'go' @('version')
    Invoke-Logged 'go-env' 'go' @('env')
    Invoke-Logged 'go-mod-verify' 'go' @('mod', 'verify')
    Invoke-Logged 'go-mod-tidy' 'go' @('mod', 'tidy', '-diff')
    Invoke-Logged 'go-vet' 'go' @('vet', './...')
    Invoke-Logged 'go-vet-e2e' 'go' @('vet', '-tags=e2e', './...')
    Invoke-Logged 'unit-tests' 'go' @('test', '-count=1', '-timeout', '2m', './...')

    $listPath = Join-Path $ArtifactDir 'offline-test-list.log'
    $listed = & go test -tags=e2e -list '^TestTorOffline' .
    $listExit = $LASTEXITCODE
    $listed | Tee-Object -FilePath $listPath | Write-Host
    if ($listExit -ne 0) {
        throw "offline test discovery failed with exit code $listExit"
    }
    $requiredTests = @($listed | Where-Object { $_ -match '^TestTorOffline\S*$' })
    if ($requiredTests.Count -eq 0) {
        throw 'go test -list found no TestTorOffline tests'
    }

    $eventsPath = Join-Path $ArtifactDir 'offline-test-events.jsonl'
    & go test -json -count=1 -tags=e2e -run '^TestTorOffline' -v -timeout 3m . |
        Tee-Object -FilePath $eventsPath
    $testExit = $LASTEXITCODE
    if ($testExit -ne 0) {
        throw "offline tests failed with exit code $testExit"
    }
    Assert-RequiredTestEvents `
        -EventsPath $eventsPath `
        -ReadablePath (Join-Path $ArtifactDir 'offline-tests.log') `
        -RequiredTests $requiredTests
    Invoke-Logged 'go-build' 'go' @('build', './...')
} finally {
    Stop-Transcript | Out-Null
}
