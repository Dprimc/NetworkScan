@echo off
setlocal
cd /d "%~dp0"
echo Building...
dotnet build -c Release
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
echo Running a quick test on localhost (127.0.0.1)...
dotnet run -c Release --project NetworkScan -- --range 127.0.0.1-127.0.0.1 --ports 22,80,443 --timeout 300
echo.
pause

