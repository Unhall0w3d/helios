$Root = if (Test-Path (Join-Path $PSScriptRoot "src")) { $PSScriptRoot } else { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
$Python = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Portable runtime is not installed. Run .\install.ps1 first."
}

& $Python (Join-Path $Root "aletheiauc.py") @args
exit $LASTEXITCODE
