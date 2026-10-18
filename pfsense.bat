@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

REM ======================================================================
REM  pfSense Checker - single launcher
REM  Sets up the venv, installs deps, and runs any component.
REM  Usage:  pfsense.bat [command] [args]
REM  Commands: setup | gui | collector | beacon | beacon-once |
REM            build-beacon | check | menu   (default: gui — login window)
REM ======================================================================

set "VENV=.venv"
set "VPY=%VENV%\Scripts\python.exe"
set "VPYW=%VENV%\Scripts\pythonw.exe"
if not exist "%VPYW%" set "VPYW=%VPY%"

REM --- locate a base Python for first-time venv creation ---
set "BASEPY="
where py >nul 2>nul && set "BASEPY=py -3"
if not defined BASEPY (
    where python >nul 2>nul && set "BASEPY=python"
)

if not exist "%VPY%" (
    if not defined BASEPY (
        echo [ERROR] Python 3 not found on PATH. Install Python 3.10+ and retry.
        exit /b 1
    )
    echo [setup] Creating virtual environment in %VENV% ...
    %BASEPY% -m venv "%VENV%"
    if errorlevel 1 ( echo [ERROR] venv creation failed & exit /b 1 )
    call :install_deps
)

REM --- dispatch on command ---
set "CMD=%~1"
if "%CMD%"=="" set "CMD=gui"

if /I "%CMD%"=="setup"         goto do_setup
if /I "%CMD%"=="gui"           goto do_gui
if /I "%CMD%"=="collector"     goto do_collector
if /I "%CMD%"=="beacon"        goto do_beacon
if /I "%CMD%"=="beacon-once"   goto do_beacon_once
if /I "%CMD%"=="build-beacon"  goto do_build_beacon
if /I "%CMD%"=="check"         goto do_check
if /I "%CMD%"=="menu"          goto menu
echo [ERROR] Unknown command: %CMD%
goto usage

:install_deps
echo [setup] Upgrading pip and installing requirements ...
"%VPY%" -m pip install --upgrade pip >nul
"%VPY%" -m pip install -r requirements.txt
exit /b 0

:do_setup
call :install_deps
echo [setup] Done.
exit /b 0

:do_gui
REM Detach silently via VBS so this console closes and only the splash shows.
wscript //nologo "%~dp0launch.vbs" %2 %3 %4 %5
exit /b 0

:do_collector
REM pfsense.bat collector [port] [token]
set "PORT=%~2"
if "%PORT%"=="" set "PORT=8787"
if "%~3"=="" (
    "%VPY%" run_collector.py --host 0.0.0.0 --port %PORT%
) else (
    "%VPY%" run_collector.py --host 0.0.0.0 --port %PORT% --token %~3
)
exit /b %errorlevel%

:do_beacon
REM pfsense.bat beacon <config.json>
if "%~2"=="" ( echo [ERROR] usage: pfsense.bat beacon ^<config.json^> & exit /b 1 )
"%VPY%" run_beacon.py --config "%~2"
exit /b %errorlevel%

:do_beacon_once
if "%~2"=="" ( echo [ERROR] usage: pfsense.bat beacon-once ^<config.json^> & exit /b 1 )
"%VPY%" run_beacon.py --config "%~2" --once
exit /b %errorlevel%

:do_build_beacon
REM pfsense.bat build-beacon [--config x | --beacon-id id --collector url] ...
set "ARGS=%*"
set "ARGS=!ARGS:*build-beacon=!"
"%VPY%" -m pfsense_checker.beacon_builder !ARGS!
exit /b %errorlevel%

:do_check
REM pfsense.bat check <config.xml>
if "%~2"=="" ( echo [ERROR] usage: pfsense.bat check ^<config.xml^> & exit /b 1 )
"%VPY%" -m pfsense_checker.cli "%~2"
exit /b %errorlevel%

:usage
echo.
echo Usage: pfsense.bat [command]
echo   (no args) / gui [config.xml]  Launch NetCheck GUI silently (splash only, no console)
echo   menu                          Tools menu (collector/beacon/check — no app login)
echo   setup                         Create venv and install dependencies
echo   collector [port] [token]      Start monitoring collector (no app login)
echo   beacon ^<config.json^>          Run a beacon loop (no app login)
echo   beacon-once ^<config.json^>     Single beacon cycle (no app login)
echo   build-beacon [options]        Generate beacon bundle (no app login)
echo   check ^<config.xml^>            Headless config report (no app login)
echo.
exit /b 0

:menu
echo.
echo ===============================================
echo   pfSense Checker — tools
echo ===============================================
echo   --- requires NetCheck login ---
echo   1^) Launch GUI (splash + login)
echo.
echo   --- no app login needed ---
echo   2^) Start monitoring collector
echo   3^) Run a beacon (loops)
echo   4^) Run a beacon once (test)
echo   5^) Generate a beacon bundle
echo   6^) Check a config.xml (headless report)
echo   7^) Reinstall dependencies
echo   0^) Exit
echo ===============================================
echo Tip: bare pfsense.bat opens the GUI directly.
set "SEL="
set /p "SEL=Select an option: "

if "%SEL%"=="1" ( wscript //nologo "%~dp0launch.vbs" & goto menu )
if "%SEL%"=="2" (
    set "P="
    set /p "P=Port [8787]: "
    if "!P!"=="" set "P=8787"
    "%VPY%" run_collector.py --host 0.0.0.0 --port !P!
    goto menu
)
if "%SEL%"=="3" (
    set "C="
    set /p "C=Path to beacon config.json: "
    if not "!C!"=="" "%VPY%" run_beacon.py --config "!C!"
    goto menu
)
if "%SEL%"=="4" (
    set "C="
    set /p "C=Path to beacon config.json: "
    if not "!C!"=="" "%VPY%" run_beacon.py --config "!C!" --once
    pause
    goto menu
)
if "%SEL%"=="5" (
    set "BID="
    set "URL="
    set /p "BID=Beacon ID [beacon-01]: "
    if "!BID!"=="" set "BID=beacon-01"
    set /p "URL=Collector URL [http://COLLECTOR_HOST:8787]: "
    if "!URL!"=="" set "URL=http://COLLECTOR_HOST:8787"
    "%VPY%" -m pfsense_checker.beacon_builder --beacon-id "!BID!" --collector "!URL!" --out beacons
    pause
    goto menu
)
if "%SEL%"=="6" (
    set "X="
    set /p "X=Path to config.xml: "
    if not "!X!"=="" "%VPY%" -m pfsense_checker.cli "!X!"
    pause
    goto menu
)
if "%SEL%"=="7" ( call :install_deps & pause & goto menu )
if "%SEL%"=="0" ( exit /b 0 )
echo Invalid selection.
goto menu
