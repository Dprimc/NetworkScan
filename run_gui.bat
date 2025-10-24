@echo off
setlocal
cd /d "%~dp0"
echo Building GUI...
dotnet build -c Release NetworkScan.Gui\NetworkScan.Gui.csproj 1>nul
if errorlevel 1 (
  echo Build failed. Please run: dotnet build -c Release
  pause
  exit /b 1
)
set EXE=NetworkScan.Gui\bin\Release\net9.0-windows\NetworkScan.Gui.exe
if not exist "%EXE%" (
  echo GUI executable not found. Trying to run via dotnet.
  echo If a console shows an error about Desktop Runtime, install it:
  echo   winget install Microsoft.DotNet.DesktopRuntime.9
  dotnet run -c Release --project NetworkScan.Gui\NetworkScan.Gui.csproj
  echo.
  echo Press any key to close...
  pause >nul
  exit /b
)
echo Launching GUI...
start "NetworkScan GUI" "%EXE%"
echo Launched. If nothing appears, you likely need .NET Desktop Runtime 9.
echo Install with: winget install Microsoft.DotNet.DesktopRuntime.9
echo.
pause
