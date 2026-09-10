<#
.SYNOPSIS
    Install the `standard-ddg` agent preset into the DeepSeek Harness home
    (%USERPROFILE%\.dsh) and make it the default for new sessions.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-preset.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install-preset.ps1 -NoDefault
#>
[CmdletBinding()]
param([switch]$NoDefault)

$ErrorActionPreference = 'Stop'
$Preset = 'standard-ddg'
$Src = Join-Path (Split-Path $PSScriptRoot -Parent) "presets\$Preset"
$DshHome = if ($env:DSH_HOME -and $env:DSH_HOME.Trim()) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$Dest = Join-Path $DshHome ".agent-presets\$Preset"
$Settings = Join-Path $DshHome 'settings.yaml'
$Utf8NoBom = New-Object Text.UTF8Encoding $false

if (-not (Test-Path (Join-Path $Src 'agent.cordis.yml'))) { throw "missing $Src\agent.cordis.yml" }
New-Item -ItemType Directory -Path $Dest -Force | Out-Null
Copy-Item (Join-Path $Src 'agent.cordis.yml'), (Join-Path $Src 'preset.yml') $Dest -Force
Write-Host "Installed preset: $Dest"

if ($NoDefault) { return }

$block = "agent-presets:`n  default: $Preset`n"
$current = if (Test-Path $Settings) { [IO.File]::ReadAllText($Settings) } else { '' }
if ([string]::IsNullOrWhiteSpace($current) -or $current.Trim() -eq '{}') {
    [IO.File]::WriteAllText($Settings, $block, $Utf8NoBom)
    Write-Host "Default preset set in $Settings"
} elseif ($current -match '(?m)^agent-presets:') {
    if ($current -match "(?m)^\s+default:\s*$Preset\s*$") {
        Write-Host "Default preset already $Preset"
    } else {
        Write-Host "$Settings already has an agent-presets section; set its default to $Preset by hand:"
        Write-Host "  agent-presets:`n    default: $Preset"
    }
} else {
    $sep = if ($current.EndsWith("`n")) { "`n" } else { "`n`n" }
    [IO.File]::WriteAllText($Settings, $current + $sep + $block, $Utf8NoBom)
    Write-Host "Default preset set in $Settings"
}
Write-Host "New sessions now use '$Preset'; running sessions keep their preset."
