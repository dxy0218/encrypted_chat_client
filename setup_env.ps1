$ErrorActionPreference = 'Stop'

param([string]$PythonVersion = '')

$win = [System.Environment]::OSVersion.Version
Write-Host "Detected Windows version: $($win.Major).$($win.Minor)"

function Ensure-PackageManager {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return 'winget' }
    if (Get-Command choco -ErrorAction SilentlyContinue) { return 'choco' }
    Write-Host 'No package manager (winget or chocolatey) found. Installing Chocolatey...'
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    if (Get-Command choco -ErrorAction SilentlyContinue) { return 'choco' }
    throw 'Failed to install Chocolatey.'
}

$PackageManager = Ensure-PackageManager

function Ensure-Program($command, $wingetId, $chocoPkg, $version) {
    if (Get-Command $command -ErrorAction SilentlyContinue) { return }
    Write-Host "$command not found. Attempting installation..."
    if ($PackageManager -eq 'winget') {
        winget install -e --id $wingetId
    } else {
        if ($version) {
            choco install $chocoPkg -y --version $version
        } else {
            choco install $chocoPkg -y
        }
    }
}

$wingetId = if ($PythonVersion) {"Python.Python.$PythonVersion"} else {"Python.Python.3"}
Ensure-Program python $wingetId 'python' $PythonVersion

$pythonCmd = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $pythonCmd) {
    $pythonCmd = (Get-Command py -ErrorAction SilentlyContinue)
    if (-not $pythonCmd) { throw 'Python installation failed. Please install manually.' }
    $pythonExe = 'py'
} else {
    $pythonExe = 'python'
}

& $pythonExe 'build_windows_installer.py'
