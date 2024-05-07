# PowerShell script to execute a list of executables from a text file in the background, log the execution, and attempt to abort unexpected shutdowns

$filePath = "C:\Users\User\Desktop\DLLResearch\WinSxSBins.txt"
$logPath = Join-Path (Split-Path -Parent $filePath) "execution_log.txt"

if (-Not (Test-Path $filePath)) {
    $errorMessage = "File not found: $filePath"
    Write-Error $errorMessage
    Add-Content -Path $logPath -Value $errorMessage
    exit
}

function Abort-Shutdown {
    Start-Process "shutdown" -ArgumentList "/a" -NoNewWindow
}

Get-Content $filePath | ForEach-Object {
    $exePath = $_.Trim()
    $logEntry = ""

    if (Test-Path $exePath) {
        try {
            Abort-Shutdown

            Start-Process -FilePath $exePath -NoNewWindow -PassThru
            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Started in background: $exePath"
        } catch {
            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Failed to start: $exePath. Error: $_"
        }
    } else {
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Executable not found: $exePath"
    }

    Write-Host $logEntry
    Add-Content -Path $logPath -Value $logEntry
}
