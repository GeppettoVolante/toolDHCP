# Builds toolDHCP as a portable folder (PyInstaller --onedir) plus a zip, in build-out\dist\
# onedir instead of onefile: no self-extraction to %TEMP% at every start, which is what
# antivirus/EDR products dislike most. The exe carries icon and version info.
# Requires: pip install pyinstaller customtkinter pillow
$version = "2.0"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out  = Join-Path $here "build-out"
$dist = Join-Path $out "dist"
New-Item -ItemType Directory -Force $out | Out-Null

# Windows version resource (Details tab of the exe properties)
$vt = (($version.Split('.') + @('0', '0', '0'))[0..3]) -join ', '
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($vt), prodvers=($vt), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'GeppettoVolante'),
      StringStruct('FileDescription', 'toolDHCP - BOOTP/DHCP and EtherNet/IP commissioning tool'),
      StringStruct('FileVersion', '$version'),
      StringStruct('InternalName', 'toolDHCP'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'toolDHCP.exe'),
      StringStruct('ProductName', 'toolDHCP'),
      StringStruct('ProductVersion', '$version')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@ | Set-Content -Encoding UTF8 (Join-Path $out "version_info.txt")

Push-Location (Join-Path $here "src")
try {
    # PyInstaller logs to stderr: with "Stop" Windows PowerShell 5.1 would abort on the first INFO line,
    # so check the exit code instead.
    $ErrorActionPreference = "Continue"
    python -m PyInstaller --onedir --windowed --name toolDHCP `
        --icon (Join-Path $here "assets\icon.ico") `
        --add-data ((Join-Path $here "assets") + ";assets") `
        --collect-all customtkinter `
        --version-file (Join-Path $out "version_info.txt") `
        --distpath $dist `
        --workpath (Join-Path $out "work") `
        --specpath $out `
        --noconfirm gui.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit code $LASTEXITCODE)" }
} finally { Pop-Location }

$zip = Join-Path $dist "toolDHCP-v$version-win64.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $dist "toolDHCP") -DestinationPath $zip
$h = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
Write-Host "Folder: $dist\toolDHCP\toolDHCP.exe"
Write-Host "Zip:    $zip"
Write-Host "SHA-256 (zip): $h"
