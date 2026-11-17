@echo off
rem Zet automatisch starten bij aanmelden uit voor AEROCX Blackout.
start "" /wait "%~dp0aerocx-blackout.exe" -autostart=off
if errorlevel 1 (
  echo Dat lukte niet. Je kunt het ook uitzetten in de app, bij Instellingen.
) else (
  echo Goed. AEROCX Blackout start niet meer vanzelf.
)
echo.
pause
