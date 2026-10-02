# NetSentinel auto-start launcher (used by the "NetSentinel-App" scheduled task).
# Sets UTF-8 console encoding (avoids the cp1252 crash on Windows) and keeps
# restarting the Flask server if it ever exits, so the app effectively never
# stays down after a login/restart.

Set-Location $PSScriptRoot
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

while ($true) {
    "$(Get-Date -Format o)  [launcher] starting server.py" | Out-File -Append -FilePath server.log -Encoding utf8
    & ".\.venv\Scripts\python.exe" server.py *>> server.log
    "$(Get-Date -Format o)  [launcher] server.py exited (code $LASTEXITCODE) - restarting in 5s" | Out-File -Append -FilePath server.log -Encoding utf8
    Start-Sleep -Seconds 5
}
