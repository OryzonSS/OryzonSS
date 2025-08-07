<#
.SYNOPSIS
    Scans Windows Prefetch for Java-related activity since last boot, analyzes with PECmd, and inspects imported modules for signature and existence status.

.DESCRIPTION
    Downloads PECmd.exe if missing, locates prefetch files for specified process names updated since last boot, parses them with PECmd, extracts imported file paths, normalizes VOLUME paths, checks if files exist, and validates Authenticode signatures.
    Provides color-coded, time-stamped output and a summary at the end.

.PARAMETER ProcessNames
    Array of process name stems (without ".exe") to look for (default: 'java','javaw').

.EXAMPLE
    .\Analyze-JavaPrefetch.ps1 -ProcessNames "java","javaw"
#>

param (
    [string[]]$ProcessNames = @("java", "javaw")
)

function Write-Log {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Download-PECmd {
    param (
        [string]$Destination
    )
    $url = 'https://github.com/NoDiff-del/JARs/releases/download/Jar/PECmd.exe'
    if (-not (Test-Path $Destination)) {
        Write-Log "Downloading PECmd.exe..." "DarkYellow"
        try {
            Invoke-RestMethod $url -OutFile $Destination
            Write-Log "PECmd.exe downloaded to $Destination" "Green"
        } catch {
            Write-Log "Failed to download PECmd.exe: $_" "Red"
            throw
        }
    } else {
        Write-Log "PECmd.exe already present at $Destination" "Gray"
    }
}

function Get-JavaPrefetchFiles {
    param (
        [DateTime]$Since,
        [string[]]$Names
    )
    $pfDir = "$env:SystemRoot\Prefetch"
    $pattern = ($Names | ForEach-Object { "$_\.pf" }) -join "|"
    Get-ChildItem $pfDir -Filter "*.pf" | Where-Object {
        $_.Name -imatch $pattern -and $_.LastWriteTime -gt $Since
    }
}

function Parse-PECmdImports {
    param (
        [string[]]$PECmdOutput
    )
    $importLines = $PECmdOutput | Where-Object { $_ -match '\\VOLUME|:\\\\' }
    $normalized = @()
    foreach ($line in $importLines) {
        $norm = $line -replace '\\VOLUME{[^}]+}', 'C:' -replace '^\d+: ', '' | ForEach-Object { $_.Trim() }
        if ($norm -match '\\[^\\]+\.[^\\]+$') {
            $normalized += $norm
        }
    }
    return $normalized | Select-Object -Unique
}

function Check-FileStatus {
    param (
        [string]$FilePath
    )
    if (Test-Path $FilePath) {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig.Status -eq 'Valid') {
            return @{Status="SIGNED"; Path=$FilePath; Signer=$sig.SignerCertificate.Subject}
        } else {
            return @{Status="UNSIGNED"; Path=$FilePath; Reason=$sig.StatusMessage}
        }
    } else {
        return @{Status="MISSING"; Path=$FilePath}
    }
}

# --- Main Script ---

$exeTemp = Join-Path $env:TEMP 'PECmd.exe'
Download-PECmd -Destination $exeTemp

$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

Write-Log "Looking for prefetch files for: $($ProcessNames -join ', ') updated since $bootTime" "Cyan"
$files = Get-JavaPrefetchFiles -Since $bootTime -Names $ProcessNames

if (-not $files) {
    Write-Log "No relevant prefetch files found. Exiting." "Yellow"
    return
}

$stats = @{
    FilesProcessed = 0
    ImportsFound = 0
    Signed = 0
    Unsigned = 0
    Missing = 0
}

foreach ($pf in $files | Sort-Object LastWriteTime -Descending) {
    $stats.FilesProcessed++
    Write-Log "`nAnalyzing $($pf.Name) (LastWrite: $($pf.LastWriteTime))" "Magenta"
    try {
        $result = & $exeTemp -f $pf.FullName 2>&1
    } catch {
        Write-Log "Failed to analyze $($pf.Name): $_" "Red"
        continue
    }

    $imports = Parse-PECmdImports -PECmdOutput $result
    if (-not $imports) {
        Write-Log "No imports detected in $($pf.Name)." "DarkGray"
        continue
    }

    Write-Log "Found $($imports.Count) imported file reference(s)." "DarkYellow"
    $stats.ImportsFound += $imports.Count

    foreach ($import in $imports) {
        $status = Check-FileStatus -FilePath $import
        switch ($status.Status) {
            "SIGNED" {
                Write-Host "[SIGNED] $($status.Path) -- Signer: $($status.Signer)" -ForegroundColor Green
                $stats.Signed++
            }
            "UNSIGNED" {
                Write-Host "[UNSIGNED] $($status.Path) -- Reason: $($status.Reason)" -ForegroundColor Red
                $stats.Unsigned++
            }
            "MISSING" {
                Write-Host "[MISSING] $($status.Path)" -ForegroundColor DarkGray
                $stats.Missing++
            }
        }
    }
}

# --- Summary ---
Write-Host "`n================ SUMMARY ================" -ForegroundColor Cyan
Write-Host "Prefetch files processed: $($stats.FilesProcessed)" -ForegroundColor Cyan
Write-Host "Total imports found:      $($stats.ImportsFound)" -ForegroundColor Yellow
Write-Host "Signed files:            $($stats.Signed)" -ForegroundColor Green
Write-Host "Unsigned files:          $($stats.Unsigned)" -ForegroundColor Red
Write-Host "Missing files:           $($stats.Missing)" -ForegroundColor DarkGray
Write-Host "=========================================" -ForegroundColor Cyan
