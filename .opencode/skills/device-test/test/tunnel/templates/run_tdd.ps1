# ============================================================================
# run_tdd.ps1 - RK3568 TDD test runner (Windows side, one-click)
#
# Windows 侧目录布局（本脚本随 kit 解压到 C:\Users\<user>\rk3568\）:
#   rk3568\
#     +- run_tdd.ps1                <- this script
#     +- reports\                   <- generated test reports (auto-pulled back)
#     +- Test\
#         +- developer_test\        <- test framework (from server test/testfwk/developer_test)
#         +- xdevice\               <- framework dependency (from server test/testfwk/xdevice)
#         +- testcase\tests\        <- compiled TDD test binaries
#
# Prerequisites (one-time):
#   1. Python 3.8+ in PATH
#   2. hdc.exe (SDK toolchains) in PATH
#   3. RK3568 board connected via USB, system booted
#
# Usage (normally invoked by run_and_report.bat):
#   powershell -ExecutionPolicy Bypass -File .\run_tdd.ps1
#   powershell -ExecutionPolicy Bypass -File .\run_tdd.ps1 -TestArgs "run -t UT -tp startup"
# ============================================================================

param(
    [string]$TestArgs = "run -t UT -p rk3568",   # 由服务端 run_tdd.sh 注入 -ts <目标>
    [string]$Hdc = "hdc",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

function Require-Cmd {
    param($cmd, $hint)
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "[ERROR] '$cmd' not found in PATH. $hint" -ForegroundColor Red
        exit 1
    }
}

# ---------- 0. checks ----------
Require-Cmd $Python "Install Python 3.8+ and add to PATH."
Require-Cmd $Hdc "Get hdc.exe from SDK toolchains and add to PATH."

# if -Hdc is a full path, inject its dir into PATH so framework subprocesses find it
if ($Hdc -ne "hdc" -and (Test-Path $Hdc)) {
    $env:PATH = "$(Split-Path $Hdc);$env:PATH"
    Write-Host "[OK] hdc dir injected into PATH: $(Split-Path $Hdc)"
}

$TestsDir = Join-Path $Root "Test\testcase\tests"
if (-not (Test-Path $TestsDir)) {
    Write-Host "[ERROR] missing $TestsDir - run 'git pull' first." -ForegroundColor Red
    exit 1
}
$binCount = (Get-ChildItem $TestsDir -Recurse -File | Where-Object { $_.Name -notlike "*_path.txt" }).Count
if ($binCount -eq 0) {
    Write-Host "[ERROR] no test binaries under $TestsDir." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] test binaries found: $binCount file(s)"

# ---------- 1. device check ----------
Write-Host "checking device via hdc ..."
& $Hdc kill 2>$null
Start-Sleep -Seconds 1
& $Hdc start 2>$null
Start-Sleep -Seconds 2
$targets = & $Hdc list targets 2>$null | Where-Object { $_ -and $_.Trim() -ne "" -and $_ -notmatch "Empty" }
if (-not $targets) {
    Write-Host "[ERROR] no device found by hdc. Check USB cable/driver, make sure the board is booted." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] device(s): $targets"

# ---------- 2. configure user_config.xml ----------
$CfgPath = Join-Path $Root "Test\developer_test\config\user_config.xml"
if (-not (Test-Path $CfgPath)) { Write-Host "[ERROR] missing $CfgPath" -ForegroundColor Red; exit 1 }
$content = Get-Content $CfgPath -Raw
$content = $content -replace '(?s)<testcase>\s*\w+\s*</testcase>', '<testcase>false</testcase>'
if ($content -match '<dir>\s*\S') {
    $content = $content -replace '(?s)<dir>.*?</dir>', "<dir>$TestsDir</dir>"
} else {
    $content = $content.Replace('<dir></dir>', "<dir>$TestsDir</dir>")
}
Set-Content -Path $CfgPath -Value $content -Encoding UTF8
Write-Host "[OK] user_config.xml -> test_cases dir: $TestsDir"

# ---------- 3. snapshot existing report dirs (to extract ONLY this run later) ----------
$reportsBase = Join-Path $Root "Test\developer_test\reports"
$before = @()
if (Test-Path $reportsBase) {
    $before = @(Get-ChildItem $reportsBase -Directory | Select-Object -ExpandProperty Name)
}

# ---------- 4. run tests ----------
$FrameworkSrc = Join-Path $Root "Test\developer_test\src"
if (-not (Test-Path (Join-Path $FrameworkSrc "main"))) {
    Write-Host "[ERROR] framework broken: $FrameworkSrc\main not found" -ForegroundColor Red
    exit 1
}
Push-Location $FrameworkSrc
$exitCode = 1
try {
    Write-Host ""
    Write-Host ">>> python -m main $TestArgs" -ForegroundColor Cyan
    Write-Host ""
    $cmdArgs = $TestArgs.Trim() -split '\s+'
    & $Python -m main @cmdArgs
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

# ---------- 5. collect ONLY this run's report ----------
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path $Root "reports"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$thisRun = $null
if (Test-Path $reportsBase) {
    $newDirs = @(Get-ChildItem $reportsBase -Directory | Where-Object { $before -notcontains $_.Name })
    if ($newDirs.Count -gt 0) {
        $thisRun = $newDirs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
}
if (-not $thisRun) {
    # fallback: newest report dir (e.g. framework reused an existing dir)
    $thisRun = Get-ChildItem $reportsBase -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if ($thisRun) {
    $zip = Join-Path $outDir "tdd_reports_$stamp.zip"
    Compress-Archive -Path $thisRun.FullName -DestinationPath $zip -Force
    Write-Host ""
    Write-Host "[DONE] report (this run only): $zip" -ForegroundColor Green
} else {
    Write-Host "[WARN] no report dir found under $reportsBase - framework may have failed early" -ForegroundColor Yellow
}
exit $exitCode
