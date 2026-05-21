# Upload local fine-tuned weights to Hugging Face *Model* repos (not the Space repo).
# Create empty Model repos first on huggingface.co/new (type: Model).
#
# Usage:
#   .\scripts\upload-hf-models.ps1 -SecureRepo "Mohd1314234123/phishshield-securebert"
#   .\scripts\upload-hf-models.ps1 -MurilRepo "Mohd1314234123/phishshield-muril"

param(
    [string]$SecureRepo = "Mohd1314234123/phishshield-securebert",
    [string]$MurilRepo = "Mohd1314234123/phishshield-muril",
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [switch]$SecureOnly,
    [switch]$MurilOnly
)

$ErrorActionPreference = "Stop"
$py = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "Missing venv python at $py"
}
$args = @("$RepoRoot\scripts\upload_hf_models.py", "--secure-repo", $SecureRepo, "--muril-repo", $MurilRepo)
if ($SecureOnly) { $args += "--secure-only" }
if ($MurilOnly) { $args += "--muril-only" }
Write-Host "Uploading model weights (~1.4 GB total, 15-40 min)..." -ForegroundColor Cyan
& $py @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Add these HF Space *Secrets*:" -ForegroundColor Green
Write-Host "  PHISHSHIELD_SECUREBERT_HF_REPO=$SecureRepo"
Write-Host "  PHISHSHIELD_MURIL_HF_REPO=$MurilRepo"
Write-Host "Then Restart Space."
