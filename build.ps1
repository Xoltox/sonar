[CmdletBinding()]
param(
    [string]$Version = ""
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if (-not $Version) {
    $Version = "dev"
    try {
        $ErrorActionPreference = 'Continue'
        $d = (& git describe --tags --always --dirty 2>$null)
        if ($LASTEXITCODE -eq 0 -and $d) { $Version = ($d | Select-Object -First 1).Trim() }
    } catch { }
    $ErrorActionPreference = 'Stop'
}

$targets = @(
    @{ OS = 'windows'; Arch = 'amd64' },
    @{ OS = 'windows'; Arch = 'arm64' },
    @{ OS = 'linux';   Arch = 'amd64' },
    @{ OS = 'linux';   Arch = 'arm64' },
    @{ OS = 'darwin';  Arch = 'amd64' },
    @{ OS = 'darwin';  Arch = 'arm64' }
)

$dist = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
$failed = $false
$names = @()

try {
    $env:CGO_ENABLED = '0'
    foreach ($t in $targets) {
        $name = "sonar-$($t.OS)-$($t.Arch)"
        if ($t.OS -eq 'windows') { $name += '.exe' }
        $env:GOOS = $t.OS
        $env:GOARCH = $t.Arch
        Write-Host "building $name ($Version)"
        & go build -trimpath -ldflags "-s -w -X main.version=$Version" -o (Join-Path $dist $name) .
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED: $name" -ForegroundColor Red
            $failed = $true
        } else {
            $names += $name
        }
    }
} finally {
    if ($null -eq $oldGoos) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $oldGoos }
    if ($null -eq $oldGoarch) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $oldGoarch }
    if ($null -eq $oldCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $oldCgo }
}

if ($failed) { exit 1 }

$lines = foreach ($n in ($names | Sort-Object)) {
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dist $n)).Hash.ToLower()
    "$h  $n"
}
$text = ($lines -join "`n") + "`n"
[System.IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS'), $text, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "wrote dist/SHA256SUMS"
exit 0
