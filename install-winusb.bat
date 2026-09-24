@echo off
rem ===========================================================================
rem  install-winusb.bat -- bind Sony VGP-URM10 (VID_054C/PID_0883) to WinUSB
rem
rem  Why: Chrome/Edge WebUSB can only see devices that are bound to the
rem       generic WinUSB driver. A clean Windows does NOT bind it automatically
rem       for this device (it does not advertise the MS OS "WINUSB" descriptor),
rem       so a 2 KB INF is needed once.
rem
rem  Usage: put this .bat NEXT TO vgp-urm10-winusb.inf and double-click it.
rem         It will ask for administrator rights and run pnputil.
rem
rem  Note: no vendor kernel driver is installed. This only re-uses the
rem        in-box winusb.inf / winusb.sys that ships with Windows.
rem ===========================================================================
setlocal
set "INF=%~dp0vgp-urm10-winusb.inf"

if not exist "%INF%" (
    echo.
    echo [ERROR] vgp-urm10-winusb.inf not found in the same folder as this script.
    echo         Download both files into the same folder and run again.
    echo.
    pause
    exit /b 1
)

rem ---- check for administrator rights ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" >nul 2>&1
    exit /b
)

echo.
echo Installing WinUSB driver for Sony VGP-URM10 ...
echo INF: %INF%
echo.
pnputil /add-driver "%INF%" /install
set RC=%errorlevel%
echo.
if %RC%==0 (
    echo [OK] Driver installed.
    echo      If the adapter is already plugged in, unplug and replug it,
    echo      then reload the web page and click "Connect device" again.
) else (
    echo [WARN] pnputil exited with code %RC%.
    echo        Windows x64 may refuse an unsigned INF.
    echo        Alternatives:
    echo          1^) install Sony's original driver package (EP0000311568.exe)
    echo          2^) use Zadig (https://zadig.akeo.ie) and pick WinUSB
)
echo.
pause
