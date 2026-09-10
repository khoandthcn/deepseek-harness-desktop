<#
.SYNOPSIS
    Read-only diagnosis for a DeepSeek Harness Desktop first start that stays on
    "Setting up DeepSeek Harness...". Deletes nothing; writes a report file.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File diagnose-windows.ps1
#>
$ErrorActionPreference = 'Continue'
$report = Join-Path ([Environment]::GetFolderPath('Desktop')) 'dsh-diagnosis.txt'
$dsh = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$desktop = Join-Path $dsh 'desktop'

function Section($title) { "`n===== $title =====" }
function DshSize {
    if (-not (Test-Path $dsh)) { return 'missing' }
    $m = Get-ChildItem $dsh -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum
    "files=$($m.Count) MB=$([int]($m.Sum / 1MB))"
}

& {
    Section 'environment'
    "time=$(Get-Date -Format o)"
    "user=$env:USERNAME profile=$env:USERPROFILE dsh=$dsh"
    "os=$([Environment]::OSVersion.VersionString)"
    try {
        $mp = Get-MpComputerStatus
        "defender realtime=$($mp.RealTimeProtectionEnabled) onaccess=$($mp.OnAccessProtectionEnabled)"
        "defender exclusions=$((Get-MpPreference).ExclusionPath -join '; ')"
    } catch { "defender: unavailable ($_)" }
    "longpaths=$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction SilentlyContinue).LongPathsEnabled)"

    Section 'processes'
    Get-CimInstance Win32_Process |
        Where-Object { $_.Name -in 'DeepSeek Harness.exe', 'node.exe' } |
        Select-Object ProcessId, ParentProcessId, Name, CreationDate,
            @{ n = 'CPUsec'; e = { [int]((Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).CPU) } },
            @{ n = 'MB'; e = { [int]($_.WorkingSetSize / 1MB) } }, CommandLine |
        Format-List | Out-String -Width 1000

    Section 'desktop state files'
    foreach ($f in 'lock', 'pending.json') {
        $p = Join-Path $desktop $f
        if (Test-Path $p) {
            "--- $f (modified $((Get-Item $p).LastWriteTime))"
            if ((Get-Item $p).PSIsContainer) { Get-ChildItem $p -Force | Format-Table Name, Length, LastWriteTime | Out-String }
            else { Get-Content $p -Raw }
        } else { "--- $f (missing)" }
    }
    '--- staging'
    Get-ChildItem (Join-Path $desktop 'staging') -Force -ErrorAction SilentlyContinue | Format-Table Name, LastWriteTime | Out-String
    '--- rollback'
    Test-Path (Join-Path $desktop 'rollback')
    '--- active profile release'
    Get-Content (Join-Path $dsh 'profiles\desktop\desktop-release.json') -Raw -ErrorAction SilentlyContinue
    '--- top-level sizes'
    foreach ($d in (Get-ChildItem $dsh -Directory -Force -ErrorAction SilentlyContinue)) {
        $m = Get-ChildItem $d.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum
        "{0,-30} files={1,7} MB={2,6}" -f $d.Name, $m.Count, [int]($m.Sum / 1MB)
    }

    Section 'progress check (is setup still writing files?)'
    "t0: $(DshSize)"
    Start-Sleep -Seconds 30
    "t0+30s: $(DshSize)"

    Section 'recent application errors'
    Get-WinEvent -LogName Application -MaxEvents 300 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Application Error|Windows Error Reporting|Application Hang' -and $_.Message -match 'DeepSeek|node' } |
        Select-Object -First 10 | Format-List TimeCreated, ProviderName, Message | Out-String -Width 400
} *>&1 | Out-File -FilePath $report -Encoding utf8

Write-Host "Report written to $report"
