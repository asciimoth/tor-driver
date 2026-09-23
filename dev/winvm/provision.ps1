param([switch] $Install)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = 'C:\winvm'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$runs = Join-Path $root 'runs'
New-Item -ItemType Directory -Force -Path $runs | Out-Null
$taskName = 'tor-driver-winvm-provision'

if (-not $Install) {
    $source = (Get-Volume -FileSystemLabel WINVM_PROVISION).DriveLetter + ':'
    $staging = Join-Path $root 'provision'
    New-Item -ItemType Directory -Force -Path $staging | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $staging -Recurse -Force

    $script = Join-Path $staging 'provision.ps1'
    $command = "& '$script' -Install *> 'C:\winvm\provision.log'"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$command`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT1M'
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    exit 0
}

$media = Join-Path $root 'provision'

function Expand-WithTar {
    param(
        [Parameter(Mandatory)] [string] $Archive,
        [Parameter(Mandatory)] [string] $Destination
    )

    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    }
    & tar.exe -xf $Archive -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot extract $Archive with tar.exe"
    }
}

# Install the signed VirtIO drivers and QEMU Guest Agent from the reviewed ISO.
$qga = Get-Volume | Where-Object DriveLetter | ForEach-Object {
    Get-ChildItem ($_.DriveLetter + ':\') -Recurse -Filter 'qemu-ga-x86_64.msi' -ErrorAction SilentlyContinue
} | Select-Object -First 1
if (-not $qga) { throw 'VirtIO media or QEMU Guest Agent installer is absent' }
$virtioRoot = (Split-Path (Split-Path $qga.FullName -Parent) -Qualifier) + '\'
Get-ChildItem $virtioRoot -Recurse -Filter '*.inf' |
    Where-Object { $_.FullName -match '\\2k22\\amd64\\' } |
    ForEach-Object { pnputil.exe /add-driver $_.FullName /install | Out-Default }
for ($attempt = 1; $attempt -le 20; $attempt++) {
    $qgaInstall = Start-Process msiexec.exe -ArgumentList @('/i', $qga.FullName, '/qn', '/norestart') -Wait -PassThru
    if ($qgaInstall.ExitCode -in @(0, 3010)) { break }
    if ($qgaInstall.ExitCode -ne 1618 -or $attempt -eq 20) {
        throw "QEMU Guest Agent installation failed with exit code $($qgaInstall.ExitCode)"
    }
    Start-Sleep -Seconds 15
}
Set-Service qemu-ga -StartupType Automatic
Start-Service qemu-ga

Expand-Archive -LiteralPath (Join-Path $media '@@GO_FILE@@') -DestinationPath 'C:\' -Force
New-Item -ItemType Directory -Force -Path (Join-Path $root 'Tor') | Out-Null
Expand-WithTar -Archive (Join-Path $media '@@TOR_FILE@@') -Destination (Join-Path $root 'Tor')
$sshRoot = 'C:\Program Files\OpenSSH-Win64'
Expand-WithTar -Archive (Join-Path $media '@@OPENSSH_FILE@@') -Destination 'C:\Program Files'

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
[Environment]::SetEnvironmentVariable('Path', "C:\go\bin;$sshRoot;$machinePath", 'Machine')
$env:Path = "C:\go\bin;$sshRoot;$env:Path"

& (Join-Path $sshRoot 'install-sshd.ps1')
$sshKeygen = Join-Path $sshRoot 'ssh-keygen.exe'
& $sshKeygen -A
if ($LASTEXITCODE -ne 0) { throw 'Cannot generate OpenSSH host keys' }
$ed25519HostKey = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key'
if (-not (Test-Path -LiteralPath ($ed25519HostKey + '.pub'))) { throw 'OpenSSH Ed25519 host key was not generated' }
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
@'
HostKey C:/ProgramData/ssh/ssh_host_ed25519_key
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AllowUsers winvm
AuthorizedKeysFile C:/ProgramData/ssh/winvm_authorized_keys
Subsystem sftp sftp-server.exe
'@ | Set-Content -LiteralPath $sshdConfig -Encoding ascii

$password = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'aA!') -AsPlainText -Force
New-LocalUser -Name 'winvm' -Password $password -AccountNeverExpires -PasswordNeverExpires | Out-Null
$administrators = Get-LocalGroup -SID 'S-1-5-32-544'
if (Get-LocalGroupMember -Group $administrators | Where-Object Name -Match '\\winvm$') {
    throw 'The winvm test account is an administrator'
}
icacls.exe $runs /inheritance:r /grant:r 'winvm:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Default
$authorizedKeys = Join-Path $env:ProgramData 'ssh\winvm_authorized_keys'
Copy-Item -LiteralPath (Join-Path $media 'authorized_key.pub') -Destination $authorizedKeys
icacls.exe $authorizedKeys /inheritance:r /grant:r 'winvm:R' 'SYSTEM:F' | Out-Default
Set-Service sshd -StartupType Automatic
Start-Service sshd
New-NetFirewallRule -Name 'winvm-sshd' -DisplayName 'winvm sshd' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null

# Keep security controls enabled. Stop only sleep and automatic update activity.
powercfg.exe /change standby-timeout-ac 0
powercfg.exe /change hibernate-timeout-ac 0
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Manual
$updatePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $updatePolicy -Force | Out-Null
New-ItemProperty -Path $updatePolicy -Name NoAutoUpdate -PropertyType DWord -Value 1 -Force | Out-Null

$torBinary = Join-Path $root 'Tor\tor\tor.exe'
if (-not (Test-Path -LiteralPath $torBinary)) { throw 'Tor executable was not installed' }
$torText = (& $torBinary --version | Out-String)
if ($torText -notmatch 'Tor version ([0-9]+(?:\.[0-9]+)+)\b') { throw 'Cannot read the Tor version' }
$torVersion = $Matches[1]
if ($torVersion -ne '@@TOR_VERSION@@') { throw "Installed Tor version is $torVersion, not @@TOR_VERSION@@" }
$goVersion = (& go version | Out-String).Trim()
if ($goVersion -notmatch '^go version go@@GO_VERSION@@ windows/amd64$') { throw "Installed Go version is not @@GO_VERSION@@: $goVersion" }
$qgaFileVersion = (Get-Item 'C:\Program Files\qemu-ga\qemu-ga.exe').VersionInfo
$qgaVersion = $qgaFileVersion.ProductVersion
if ([string]::IsNullOrWhiteSpace($qgaVersion)) {
    $qgaVersion = $qgaFileVersion.FileVersion
}
if ([string]::IsNullOrWhiteSpace($qgaVersion)) {
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $qgaVersion = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
        Where-Object DisplayName -Match 'QEMU.*guest agent' |
        Select-Object -ExpandProperty DisplayVersion -First 1
}
if ([string]::IsNullOrWhiteSpace($qgaVersion)) { throw 'Cannot read the QEMU Guest Agent version' }
$manifest = [ordered]@{
    windowsBuild = [Environment]::OSVersion.Version.ToString()
    architecture = $env:PROCESSOR_ARCHITECTURE
    goVersion = $goVersion
    torVersion = $torVersion
    torBinary = $torBinary
    qemuGuestAgentVersion = $qgaVersion
    provisionedAt = (Get-Date).ToUniversalTime().ToString('o')
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'manifest.json') -Encoding utf8

@(
    'C:\Windows\Panther\unattend.xml',
    'C:\Windows\Panther\Unattend\unattend.xml',
    'C:\Windows\System32\Sysprep\unattend.xml'
) | ForEach-Object { Remove-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Remove-Item -LiteralPath $media -Recurse -Force
New-Item -ItemType File -Force -Path (Join-Path $root 'ready') | Out-Null
