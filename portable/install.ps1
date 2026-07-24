[CmdletBinding()]
param(
    [switch]$NoPdf,
    [string]$Python = "py"
)

$ErrorActionPreference = "Stop"
$Root = if (Test-Path (Join-Path $PSScriptRoot "src")) { $PSScriptRoot } else { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }

& $Python -c "import sys; raise SystemExit(sys.version_info < (3, 11))"
if ($LASTEXITCODE -ne 0) {
    throw "AletheiaUC requires Python 3.11 or newer. Use -Python to select it."
}

Push-Location $Root
try {
    & $Python -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip
    & .\.venv\Scripts\python.exe -m pip install -r requirements-runtime.txt
    if (-not $NoPdf) {
        & .\.venv\Scripts\python.exe -m playwright install chromium
        if ($LASTEXITCODE -eq 0) {
            Write-Host "PDF support installed."
        }
        else {
            Write-Warning "Chromium could not be installed. HTML reports are ready; run AletheiaUC with --no-pdf-report."
            Write-Warning "Retry .\install.ps1 later to add PDF support."
        }
    }
    else {
        Write-Host "HTML-only runtime installed. Run .\install.ps1 later to add PDF support."
    }
}
finally {
    Pop-Location
}

Write-Host "Ready. Run .\aletheiauc.ps1 or . .\Activate.ps1."
