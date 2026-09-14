[CmdletBinding()]
param(
    [string]$SshHost = "racknerd",
    [string]$Destination = (Join-Path $env:LOCALAPPDATA "ShuaBao\subscription-backup-mirror\vps-b"),
    [int]$MaxAgeHours = 8,
    [switch]$SkipDownload
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($SshHost -notmatch "^[A-Za-z0-9_.-]+$") {
    throw "SshHost must be an SSH config alias, not a shell expression."
}
if ($MaxAgeHours -lt 1) {
    throw "MaxAgeHours must be at least one hour."
}

$remoteArchive = "/srv/shuabao-backup/archive"
$receiptPath = Join-Path $Destination "receipt.json"

function Invoke-SshText([string]$Command) {
    $lines = @(& ssh -o BatchMode=yes -o ConnectTimeout=20 $SshHost $Command 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "SSH command failed: $($lines -join ' ')"
    }
    return $lines
}

function Invoke-SshScriptText([string]$Script) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
    return Invoke-SshText "echo $encoded | base64 -d | sudo -n sh"
}

function Copy-SshBinary([string]$Command, [string]$Path) {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = "ssh"
    $start.Arguments = "-o BatchMode=yes -o ConnectTimeout=20 $SshHost $Command"
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "Unable to start ssh."
    }

    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        try {
            $process.StandardOutput.BaseStream.CopyTo($stream)
        }
        finally {
            $stream.Dispose()
        }
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Encrypted archive transfer failed: $stderr"
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ArchiveTime([string]$Name) {
    if ($Name -notmatch "(\d{8}T\d{6}Z)") {
        return $null
    }
    return [DateTime]::ParseExact(
        $matches[1],
        "yyyyMMddTHHmmssZ",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    )
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null

$archiveNames = Invoke-SshText "sudo -n find $remoteArchive -maxdepth 1 -type f -name '*.tar.gz.age' -printf '%f`n' | LC_ALL=C sort"
$manifestScript = @'
for f in /srv/shuabao-backup/archive/*.tar.gz.age; do
    [ -f "$f" ] || continue
    b=${f##*/}
    s=/srv/shuabao-backup/archive/$b.sha256
    [ -f "$s" ] || s=/srv/shuabao-backup/incoming/$b.sha256
    [ -f "$s" ] || continue
    set -- $(sudo -n /bin/cat -- "$s")
    h=$1
    z=$(sudo -n stat -c %s "$f")
    echo "$b|$z|$h"
done | LC_ALL=C sort
'@
$rows = Invoke-SshScriptText $manifestScript
$remoteFiles = foreach ($row in $rows) {
    if ($row -notmatch "^([A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz\.age)\|(\d+)\|([0-9a-fA-F]{64})$") {
        throw "Unexpected archive listing entry."
    }
    [pscustomobject]@{
        Name = $matches[1]
        SizeBytes = [int64]$matches[2]
        Sha256 = $matches[3].ToLowerInvariant()
    }
}
if (@($remoteFiles).Count -eq 0) {
    throw "VPS-B archive directory contains no encrypted subscription backup."
}

$skippedLegacyArchives = @($archiveNames | Where-Object { $_ -notin $remoteFiles.Name })
$receiptArchives = foreach ($remote in $remoteFiles) {
    $expectedHash = $remote.Sha256
    $localPath = Join-Path $Destination $remote.Name
    $needsCopy = -not (Test-Path -LiteralPath $localPath)
    if (-not $needsCopy) {
        $needsCopy = (Get-Sha256 $localPath) -ne $expectedHash
    }
    if ($needsCopy -and -not $SkipDownload) {
        $partialPath = "$localPath.partial-$PID"
        Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
        try {
            Copy-SshBinary "sudo -n /bin/cat -- $remoteArchive/$($remote.Name)" $partialPath
            if ((Get-Sha256 $partialPath) -ne $expectedHash) {
                throw "SHA-256 mismatch after transfer for $($remote.Name)."
            }
            Move-Item -LiteralPath $partialPath -Destination $localPath -Force
        }
        finally {
            Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
        }
    }
    $localHash = if (Test-Path -LiteralPath $localPath) { Get-Sha256 $localPath } else { $null }
    [pscustomobject]@{
        name = $remote.Name
        size_bytes = $remote.SizeBytes
        sha256 = $expectedHash
        local_sha256_verified = ($localHash -eq $expectedHash)
        archive_timestamp_utc = (Get-ArchiveTime $remote.Name).ToString("o")
    }
}

if (@($receiptArchives).Count -eq 0) {
    throw "VPS-B has no encrypted archive with a SHA-256 sidecar."
}

$latest = $receiptArchives | Sort-Object archive_timestamp_utc | Select-Object -Last 1
$latestTime = [DateTime]::Parse($latest.archive_timestamp_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
$ageHours = [Math]::Round(((Get-Date).ToUniversalTime() - $latestTime).TotalHours, 2)
$receipt = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    source = "vps-b-encrypted-archive"
    ssh_host_alias = $SshHost
    latest_archive_utc = $latestTime.ToString("o")
    latest_archive_age_hours = $ageHours
    max_age_hours = $MaxAgeHours
    freshness_ok = ($ageHours -le $MaxAgeHours)
    archives = @($receiptArchives)
    excluded_archives_without_sha256_sidecar = @($skippedLegacyArchives)
}
$receipt | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $receiptPath -Encoding utf8

if (-not $receipt.freshness_ok) {
    Write-Warning "Mirror succeeded but newest VPS-B archive is stale: $ageHours hours old (limit: $MaxAgeHours)."
    exit 2
}
Write-Output "Mirror receipt written: $receiptPath"
