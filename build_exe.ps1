# Builds a portable single-file toolDHCP.exe in build-out\dist\
# Requires: pip install pyinstaller
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location (Join-Path $here "src")
try {
    # PyInstaller logs to stderr: with "Stop" Windows PowerShell 5.1 would abort on the first INFO line,
    # so check the exit code instead.
    $ErrorActionPreference = "Continue"
    python -m PyInstaller --onefile --windowed --name toolDHCP `
        --distpath (Join-Path $here "build-out\dist") `
        --workpath (Join-Path $here "build-out\work") `
        --specpath (Join-Path $here "build-out") `
        --noconfirm gui.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit code $LASTEXITCODE)" }
} finally { Pop-Location }
Write-Host "Exe: $here\build-out\dist\toolDHCP.exe"
