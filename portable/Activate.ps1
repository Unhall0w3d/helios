$Root = if (Test-Path (Join-Path $PSScriptRoot "src")) { $PSScriptRoot } else { (Resolve-Path $PSScriptRoot).Path }
$Activate = Join-Path $Root ".venv\Scripts\Activate.ps1"
if (-not (Test-Path $Activate)) {
    throw "Portable runtime is not installed. Run .\install.ps1 first."
}
. $Activate
