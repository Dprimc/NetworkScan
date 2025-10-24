@echo off
setlocal
cd /d "%~dp0"
set LOG=gui_run.log
echo [%date% %time%] Building GUI (explicit project)... > "%LOG%"
dotnet build -c Release NetworkScan.Gui\NetworkScan.Gui.csproj >> "%LOG%" 2>&1
if errorlevel 1 (
  echo Build failed. See %LOG%.
  type "%LOG%"
  pause
  exit /b 1
)
echo [%date% %time%] Launching GUI... >> "%LOG%"
set EXE=NetworkScan.Gui\bin\Release\net9.0-windows\NetworkScan.Gui.exe
if exist "%EXE%" (
  start "NetworkScan GUI" "%EXE%"
  echo Started GUI. If nothing appears, check gui_crash.log and %LOG%.
  echo Missing Desktop Runtime? Install: winget install Microsoft.DotNet.DesktopRuntime.9
  echo.
  type "%LOG%"
  pause
  exit /b
)
echo EXE not found, running via dotnet... >> "%LOG%"
dotnet run -c Release --project NetworkScan.Gui\NetworkScan.Gui.csproj >> "%LOG%" 2>&1
echo Done. Showing log:
type "%LOG%"
echo.
pause
