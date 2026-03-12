param(
    [string]$GeneratorTest = "org.example.input_security_starter.llm.analysis.AttackChainLogGeneratorTest#generateHighVolumeAttackLog",
    [string]$ProjectDir = "",
    [string]$EnvFile = ".env",
    [switch]$SkipGenerate
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor DarkGray
}

function Write-Success {
    param([string]$Message)
    Write-Host "    [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "    [WARN] $Message" -ForegroundColor Yellow
}

function Import-DotEnv {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Env file not found: $Path"
    }

    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { return }
        if ($line.StartsWith("#")) { return }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { return }

        $key = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()

        if ($value.StartsWith('"') -and $value.EndsWith('"') -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        Set-Item -Path ("Env:" + $key) -Value $value
    }
}

function Require-Env {
    param([string[]]$Keys)
    $missing = @()
    foreach ($k in $Keys) {
        $v = [Environment]::GetEnvironmentVariable($k)
        if ([string]::IsNullOrWhiteSpace($v)) {
            $missing += $k
        }
    }
    if ($missing.Count -gt 0) {
        throw ("Missing required environment variables: " + ($missing -join ", "))
    }
}

function Check-Optional-Env {
    param([string]$Key, [string]$Name)
    $v = [Environment]::GetEnvironmentVariable($Key)
    if ([string]::IsNullOrWhiteSpace($v)) {
        Write-Warn "$Name not configured ($Key)"
        return $false
    } else {
        Write-Success "$Name configured"
        return $true
    }
}

function Invoke-Maven {
    param([string[]]$MavenArgs)
    Write-Host ("mvn " + ($MavenArgs -join " ")) -ForegroundColor DarkGray
    & mvn @MavenArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Maven command failed with exit code $LASTEXITCODE"
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($ProjectDir)) {
        $ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    Set-Location $ProjectDir

    Write-Step "Loading environment variables from $EnvFile"
    Import-DotEnv -Path $EnvFile
    Require-Env -Keys @("GLM_API_KEY", "ABUSEIPDB_API_KEY")

    Write-Host ""
    Write-Host "    Notification Services Status:" -ForegroundColor Cyan
    
    $feishuEnabled = Check-Optional-Env -Key "FEISHU_APP_ID" -Name "Feishu"
    $dingtalkEnabled = Check-Optional-Env -Key "DINGTALK_WEBHOOK_URL" -Name "DingTalk (Webhook)"
    if (-not $dingtalkEnabled) {
        $dingtalkEnabled = Check-Optional-Env -Key "DINGTALK_APP_KEY" -Name "DingTalk (App API)"
    }

    if (-not $SkipGenerate) {
        Write-Step "Generating attack-chain-alerts.log using $GeneratorTest"
        Invoke-Maven -MavenArgs @("-q", "-Dtest=$GeneratorTest", "test")
    }

    if (-not (Test-Path "attack-chain-alerts.log")) {
        throw "attack-chain-alerts.log not found after generation"
    }
    $logInfo = Get-Item "attack-chain-alerts.log"
    Write-Host ("attack-chain-alerts.log size: {0} bytes" -f $logInfo.Length) -ForegroundColor Green

    Write-Step "Running LlmAnalysisTest full flow"
    Invoke-Maven -MavenArgs @(
        "-q",
        "-DskipTests",
        "compile",
        "org.codehaus.mojo:exec-maven-plugin:3.5.0:java",
        "-Dexec.mainClass=org.example.input_security_starter.LlmAnalysisTest",
        "-Dexec.classpathScope=runtime"
    )

    Write-Step "Done"
    Write-Host ""
    Write-Host "Full LLM flow completed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "Notifications sent to:" -ForegroundColor Cyan
    if ($feishuEnabled) { Write-Success "Feishu" }
    if ($wecomEnabled) { Write-Success "WeCom" }
    if ($dingtalkEnabled) { Write-Success "DingTalk" }
    if (-not ($feishuEnabled -or $wecomEnabled -or $dingtalkEnabled)) {
        Write-Warn "No notification services configured"
    }
    exit 0
}
catch {
    Write-Host ""
    Write-Host ("Full flow failed: " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
