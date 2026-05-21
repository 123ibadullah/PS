# Sync backend/ to Hugging Face Space and push (Docker Space).
# Usage:
#   .\scripts\deploy-hf-space.ps1
#   .\scripts\deploy-hf-space.ps1 -HfUser "Mohd1314234123" -Message "Deploy backend"
#
# Prerequisites: git, git-lfs, huggingface-cli login (or git credential for HF)

param(
    [string]$HfUser = "Mohd1314234123",
    [string]$SpaceName = "phishshield-backend",
    [string]$Message = "Deploy PhishShield backend (CORS, extension, scoring, Docker)",
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [switch]$SkipPush
)

$ErrorActionPreference = "Stop"
$Backend = Join-Path $RepoRoot "backend"
$SpaceDir = Join-Path $RepoRoot "phishshield-backend-space"
$Remote = "https://huggingface.co/spaces/$HfUser/$SpaceName"

Write-Host "PhishShield -> HF Space deploy" -ForegroundColor Cyan
Write-Host "  Source: $Backend"
Write-Host "  Target: $SpaceDir"
Write-Host "  Remote: $Remote"

if (-not (Test-Path $Backend)) {
    throw "backend folder not found: $Backend"
}

if (-not (Test-Path $SpaceDir)) {
    Write-Host "Cloning Space repo (first time)..." -ForegroundColor Yellow
    git lfs install 2>$null
    git clone $Remote $SpaceDir
} else {
    Write-Host "Updating Space clone..." -ForegroundColor Yellow
    Push-Location $SpaceDir
    $ErrorActionPreference = "Continue"
    git pull origin main 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { git pull 2>&1 | Out-Null }
    $ErrorActionPreference = "Stop"
    Pop-Location
}

Write-Host "Copying backend files (excluding large ML weights)..." -ForegroundColor Yellow
$robo = robocopy $Backend $SpaceDir /E `
    /XD indicbert_model "models\securebert_model" "models\muril_model" reports __pycache__ .pytest_cache .mypy_cache .venv venv `
    /XF .env *.log *.db *.db-* *.sqlite *.pyc scan_logs.jsonl feedback.csv sender_profiles.json test_results*.txt verify_output.txt `
    "*.safetensors" "*.bin" "training_args.bin" `
    /NFL /NDL /NJH /NJS /nc /ns /np

# Robocopy exit codes 0-7 are success
if ($robo -gt 7) {
    throw "robocopy failed with exit code $robo"
}

# Offline benchmark metrics for GET /api/metrics (small JSON, required on HF Space)
$TrainingMeta = Join-Path $RepoRoot "data\training_meta.json"
if (Test-Path $TrainingMeta) {
    $SpaceDataDir = Join-Path $SpaceDir "data"
    New-Item -ItemType Directory -Force -Path $SpaceDataDir | Out-Null
    Copy-Item $TrainingMeta (Join-Path $SpaceDataDir "training_meta.json") -Force
    Write-Host "  Copied data/training_meta.json for /api/metrics" -ForegroundColor DarkGray
}

# Never ship transformer weights to free HF Spaces (1 GB repo cap). Runtime uses HF_TOKEN download.
foreach ($drop in @(
    "indicbert_model",
    "models\securebert_model",
    "models\muril_model"
)) {
    $p = Join-Path $SpaceDir $drop
    if (Test-Path $p) {
        Remove-Item -Recurse -Force $p
        Write-Host "  Removed $drop from Space payload" -ForegroundColor DarkYellow
    }
}
# Keep provider Python code only
$modelsDir = Join-Path $SpaceDir "models"
if (Test-Path $modelsDir) {
    Get-ChildItem $modelsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match "_model$") {
            Remove-Item -Recurse -Force $_.FullName
            Write-Host "  Removed models\$($_.Name)" -ForegroundColor DarkYellow
        }
    }
}

$hfignoreSrc = Join-Path $PSScriptRoot "hf-space.hfignore"
if (Test-Path $hfignoreSrc) {
    Copy-Item $hfignoreSrc (Join-Path $SpaceDir ".hfignore") -Force
}

# Required for HF Docker Space routing
$readmeSrc = Join-Path $Backend "README.md"
if (Test-Path $readmeSrc) {
    Copy-Item $readmeSrc (Join-Path $SpaceDir "README.md") -Force
}

foreach ($artifact in @("model.pkl", "vectorizer.pkl")) {
    $src = Join-Path $Backend $artifact
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $SpaceDir $artifact) -Force
        Write-Host "  Included $artifact" -ForegroundColor Green
    } else {
        Write-Warning "Missing $artifact - Space will rely on HF_TOKEN model download + rules."
    }
}

Push-Location $SpaceDir
git add -A
$status = git status --porcelain
if (-not $status) {
    Write-Host "No changes to push." -ForegroundColor Green
    Pop-Location
    exit 0
}

git commit -m $Message
if ($SkipPush) {
    Write-Host "SkipPush set - commit created locally only." -ForegroundColor Yellow
    Pop-Location
    exit 0
}

Write-Host "Pushing to Hugging Face (build starts automatically)..." -ForegroundColor Cyan
git push
Pop-Location

Write-Host ""
Write-Host "Done. Next steps on HF Space Settings:" -ForegroundColor Green
Write-Host "  1. Secrets: HF_TOKEN, VT_API_KEY, GOOGLE_API_KEY, LLM_API_KEY (same as local .env)"
Write-Host "  2. Variables: ENVIRONMENT=production, PYTHONUNBUFFERED=1"
Write-Host "  3. Restart Space (or wait for build)"
Write-Host "  4. Open: https://${HfUser}-${SpaceName}.hf.space/health"
Write-Host "     securebert + muril should show ready after warmup (~2-5 min with HF_TOKEN)"
