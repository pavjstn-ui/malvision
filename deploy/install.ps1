# MalVision Agent Installer
# Run as Administrator on Windows endpoint
# Usage: .\install.ps1 -EngineUrl "https://your-vps-ip" -CompanyName "company-name"

param(
    [Parameter(Mandatory=$true)]
    [string]$EngineUrl,

    [Parameter(Mandatory=$true)]
    [string]$CompanyName
)

$ErrorActionPreference = "Stop"
$InstallDir = "C:\MalVision"
$PythonVersion = "3.11"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MalVision Agent Installer" -ForegroundColor Cyan
Write-Host "  Company: $CompanyName" -ForegroundColor Cyan
Write-Host "  Engine:  $EngineUrl" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ── Check Admin ──────────────────────────────────────────────────────────────

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# ── Install Python if needed ──────────────────────────────────────────────────

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "Installing Python $PythonVersion..." -ForegroundColor Yellow
    $installer = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile $installer
    Start-Process $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    Write-Host "Python installed." -ForegroundColor Green
} else {
    Write-Host "Python found: $($python.Source)" -ForegroundColor Green
}

# ── Create install directory ──────────────────────────────────────────────────

Write-Host "Creating $InstallDir..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\agent" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\logs" | Out-Null

# ── Install Python dependencies ───────────────────────────────────────────────

Write-Host "Installing Python packages..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet
python -m pip install watchdog psutil scipy requests --quiet
Write-Host "Packages installed." -ForegroundColor Green

# ── Download agent files ──────────────────────────────────────────────────────

Write-Host "Downloading agent..." -ForegroundColor Yellow
$BaseUrl = "$EngineUrl/agent"

# In production, agents are served from the engine URL
# For pilot, copy files manually or serve from GitHub raw URLs
$AgentFiles = @("watcher.py", "process_monitor.py")
foreach ($file in $AgentFiles) {
    $dest = "$InstallDir\agent\$file"
    # Uncomment when files are hosted:
    # Invoke-WebRequest "$BaseUrl/$file" -OutFile $dest
    Write-Host "  [manual] Copy $file to $dest" -ForegroundColor Yellow
}

# ── Write config ──────────────────────────────────────────────────────────────

$config = @"
[engine]
url = $EngineUrl
company = $CompanyName
hostname = $env:COMPUTERNAME

[honeytokens]
paths =
    C:\Users\Public\config.ini
    C:\Users\Administrator\.ssh\id_rsa
    D:\backups\accounts_payable.xlsx

[watch]
paths =
    C:\Users
    D:\
"@

$config | Out-File -FilePath "$InstallDir\config.ini" -Encoding UTF8
Write-Host "Config written to $InstallDir\config.ini" -ForegroundColor Green

# ── Plant honeytoken files ────────────────────────────────────────────────────

Write-Host "Planting honeytoken files..." -ForegroundColor Yellow

# Fake DB credentials
$dbCreds = @"
[database]
host=10.0.0.5
user=sa
password=Prod_DB_2024!
database=accounts_prod
port=1433
"@
New-Item -ItemType Directory -Force -Path "C:\Users\Public" | Out-Null
$dbCreds | Out-File -FilePath "C:\Users\Public\config.ini" -Encoding UTF8

# Fake SSH key
$fakeKey = @"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234FAKE_KEY_DO_NOT_USE_IN_PRODUCTION
[This is a decoy file. Any access should be treated as a security incident.]
-----END RSA PRIVATE KEY-----
"@
New-Item -ItemType Directory -Force -Path "C:\Users\Administrator\.ssh" | Out-Null
$fakeKey | Out-File -FilePath "C:\Users\Administrator\.ssh\id_rsa" -Encoding UTF8

# Fake financial spreadsheet placeholder
$fakeCsv = @"
Datum,Dodavatel,Castka,Mena,Poznamka
2024-01-15,Novak s.r.o.,125000,EUR,Faktura 2024-001
2024-02-03,Svoboda a.s.,87500,EUR,Faktura 2024-012
2024-03-21,Dvorak GmbH,210000,EUR,Faktura 2024-031
"@
New-Item -ItemType Directory -Force -Path "D:\backups" -ErrorAction SilentlyContinue | Out-Null
if (Test-Path "D:\") {
    $fakeCsv | Out-File -FilePath "D:\backups\accounts_payable.xlsx" -Encoding UTF8
    Write-Host "  Honeytoken planted: D:\backups\accounts_payable.xlsx" -ForegroundColor Green
}
Write-Host "  Honeytoken planted: C:\Users\Public\config.ini" -ForegroundColor Green
Write-Host "  Honeytoken planted: C:\Users\Administrator\.ssh\id_rsa" -ForegroundColor Green

# ── Create Windows Service ────────────────────────────────────────────────────

Write-Host "Registering MalVision as Windows service..." -ForegroundColor Yellow

$watcherScript = @"
import subprocess, sys, os
os.chdir(r'$InstallDir')
subprocess.run([sys.executable, r'$InstallDir\agent\watcher.py', r'C:\Users', r'D:\\'])
"@

$launcherPath = "$InstallDir\run_watcher.py"
$watcherScript | Out-File -FilePath $launcherPath -Encoding UTF8

# Register as scheduled task (runs at startup, restarts on failure)
$action = New-ScheduledTaskAction -Execute "python" -Argument $launcherPath
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "MalVisionAgent" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

# Start immediately
Start-ScheduledTask -TaskName "MalVisionAgent"
Write-Host "MalVision agent registered and started." -ForegroundColor Green

# ── Verify connectivity ───────────────────────────────────────────────────────

Write-Host "Testing engine connectivity..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$EngineUrl/health" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "Engine reachable. " -ForegroundColor Green
    }
} catch {
    Write-Host "Engine unreachable — events will queue locally until connection is restored." -ForegroundColor Yellow
}

# ── Done ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MalVision installed successfully" -ForegroundColor Cyan
Write-Host "  Install dir: $InstallDir" -ForegroundColor Cyan
Write-Host "  Logs:        $InstallDir\logs\" -ForegroundColor Cyan
Write-Host "  Honeytokens: 3 files planted" -ForegroundColor Cyan
Write-Host "  Service:     MalVisionAgent (Task Scheduler)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next: verify in Task Scheduler that MalVisionAgent is Running." -ForegroundColor White
