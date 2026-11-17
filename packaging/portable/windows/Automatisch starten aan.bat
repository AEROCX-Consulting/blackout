@echo off
rem Zet automatisch starten bij aanmelden aan voor AEROCX Blackout.
rem Let op: verplaats de map daarna niet meer (of voer dit bestand opnieuw uit).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0.' | Unblock-File" >nul 2>&1
start "" /wait "%~dp0aerocx-blackout.exe" -autostart=on
if errorlevel 1 (
  echo Dat lukte niet. Je kunt het ook aanzetten in de app, bij Instellingen.
) else (
  echo Goed. AEROCX Blackout start voortaan vanzelf als je je aanmeldt.
)
echo.
pause
