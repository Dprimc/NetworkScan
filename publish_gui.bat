@echo off
setlocal
cd /d "%~dp0"
echo Publishing self-contained GUI (win-x64)...
dotnet publish .\NetworkScan.Gui\NetworkScan.Gui.csproj -c Release -r win-x64 -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false --self-contained true
if errorlevel 1 (
  echo Publish failed.
  pause
  exit /b 1
)
echo Output:
for %%F in ("NetworkScan.Gui\bin\Release\net9.0-windows\win-x64\publish\*.exe") do (
  echo   %%~fF
)
echo.
echo Double-click the published EXE above. No separate runtime needed.
pause

