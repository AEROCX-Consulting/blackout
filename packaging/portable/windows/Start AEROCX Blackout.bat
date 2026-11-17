@echo off
rem Dubbelklik om AEROCX Blackout te starten (versie zonder installatieprogramma).
rem Haalt eerst de "gedownload van internet"-markering weg, zodat Windows niet blijft waarschuwen.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0.' | Unblock-File" >nul 2>&1
if not exist "%~dp0aerocx-blackout.exe" (
  echo Het programma aerocx-blackout.exe staat niet naast dit bestand. Pak de zip opnieuw uit.
  pause
  exit /b 1
)
rem Starten en dit venster meteen sluiten. Draait de app al, dan opent alleen je browser.
start "" "%~dp0aerocx-blackout.exe" -open
exit /b 0
