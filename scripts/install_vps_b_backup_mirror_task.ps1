[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TaskName = "ShuaBao-VPSB-BackupMirror",
    [int]$EveryHours = 6,
    [int]$MaxAgeHours = 8
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($EveryHours -lt 1 -or $MaxAgeHours -lt $EveryHours) {
    throw "EveryHours must be positive and MaxAgeHours must not be smaller."
}

$mirrorScript = Join-Path $PSScriptRoot "mirror_vps_b_backup_to_dev.ps1"
if (-not (Test-Path -LiteralPath $mirrorScript)) {
    throw "Mirror script not found: $mirrorScript"
}

$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$mirrorScript`" -MaxAgeHours $MaxAgeHours"
if ($PSCmdlet.ShouldProcess($TaskName, "register an interactive $EveryHours-hour backup mirror task")) {
    $result = & schtasks.exe /Create /TN $TaskName /SC HOURLY /MO $EveryHours /TR "powershell.exe $arguments" /RU $env:USERNAME /RL LIMITED /IT /F
    if ($LASTEXITCODE -ne 0) {
        throw "Scheduled task registration failed: $($result -join ' ')"
    }
    Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State
}
