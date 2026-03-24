@echo off
REM attach_any.bat -- Attach the dexbgd agent to a target app
REM
REM Improvements over attach.bat:
REM   - Auto-discovers the launcher activity (no hardcoded .MainActivity)
REM   - Handles split APKs (pm path returns multiple lines)
REM
REM Usage:
REM   scripts\attach_any.bat <package_name>             -- normal attach (app must be running)
REM   scripts\attach_any.bat <package_name> --quick     -- force-stop, fresh start, attach ASAP
REM   scripts\attach_any.bat <package_name> --sigstop   -- like --quick but SIGSTOP the process
REM                                                        immediately on PID appearance so agent
REM                                                        attaches while app is frozen (needs root)
REM   scripts\attach_any.bat <package_name> --ptrace    -- inject via ptrace (no repackaging, needs root)
REM
REM NOTE: --quick and --sigstop use "cmd activity attach-agent" which requires android:debuggable=true.
REM       They only work with repackaged APKs (Option A). For production apps use --ptrace instead.
REM
REM NOTE: --suspended (am start -D) does NOT work on Android 14 -- JDWP freezes the
REM       Binder thread so attach-agent is never processed.
REM       Use --sigstop instead: freezes with SIGSTOP after attach-agent, resumes after socket ready.

setlocal enabledelayedexpansion

set "TARGET_PKG=%~1"
if "%TARGET_PKG%"=="" set "TARGET_PKG=com.test.profiletest"
set "AGENT_NAME=libart_jit_tracer.so"

REM Verify package is installed
set "PKG_LINE="
for /f "tokens=*" %%A in ('adb shell pm path %TARGET_PKG% 2^>nul') do (
    if not defined PKG_LINE set "PKG_LINE=%%A"
)
if not defined PKG_LINE (
    echo ERROR: Package %TARGET_PKG% not found on device
    exit /b 1
)
echo [*] Package: %TARGET_PKG%

REM Resolve the launcher activity.
REM IMPORTANT: tr -d '\r' must use single quotes in bash -- without them bash interprets
REM            \r as escaped-r and strips all 'r' characters instead of carriage returns.
REM Note: | inside a double-quoted adb shell string is safe -- cmd.exe treats it as
REM       literal inside double quotes, and the shell on the device interprets it as a pipe.
set "MAIN_ACTIVITY="
for /f "tokens=*" %%A in ('adb shell "cmd package resolve-activity --brief -c android.intent.category.LAUNCHER %TARGET_PKG% 2>/dev/null | grep / | tail -1 | tr -d '\r'"') do set "MAIN_ACTIVITY=%%A"
if defined MAIN_ACTIVITY (
    echo [*] Launcher: %MAIN_ACTIVITY%
) else (
    echo [*] Could not resolve launcher activity
)

REM Use monkey to launch -- handles alias activities, split APKs, non-standard launchers.
REM Equivalent to tapping the app icon. monkey -p pkg -c LAUNCHER 1 sends exactly one
REM launcher event and always works regardless of how the manifest is structured.
set "START_CMD=monkey -p %TARGET_PKG% -c android.intent.category.LAUNCHER 1"

REM Derive .so path from first pm path line only (handles split APKs).
REM   package:/data/app/~~HASH/com.pkg-1/base.apk  (first line)
REM   ->  /data/app/~~HASH/com.pkg-1/lib/arm64/libart_jit_tracer.so
REM Use cut to strip "package:" prefix then dirname in the shell.
REM (| inside double-quoted string: safe, see note above)
set "SO_PATH="
for /f "tokens=*" %%S in ('adb shell "d=$(pm path %TARGET_PKG% | head -n1 | cut -d: -f2 | tr -d '\r'); echo $(dirname $d)/lib/arm64/%AGENT_NAME%"') do set "SO_PATH=%%S"
if defined SO_PATH (
    echo [*] .so path: %SO_PATH%
) else (
    echo ERROR: Could not resolve .so path for %TARGET_PKG%
    exit /b 1
)

if /i "%~2"=="--quick"    goto :quick
if /i "%~2"=="--sigstop"  goto :sigstop
if /i "%~2"=="--ptrace"   goto :ptrace

REM ---- Normal path: ensure app is running, then attach -------------------------
set "PID="
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID (
    echo [*] App not running, starting it...
    adb shell !START_CMD!
    timeout /t 2 /nobreak >nul
    for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
    if not defined PID (
        echo ERROR: Failed to start %TARGET_PKG%
        exit /b 1
    )
)
echo [*] PID: !PID!
echo [*] Attaching agent...
adb shell cmd activity attach-agent %TARGET_PKG% %AGENT_NAME%
echo [*] Agent attached.
goto :eof

REM ---- Quick path: fresh start, attach as fast as possible --------------------
:quick
echo [*] Pre-establishing port forward...
adb forward tcp:12345 localabstract:dexbgd

echo [*] Force-stopping %TARGET_PKG%...
adb shell am force-stop %TARGET_PKG%
timeout /t 1 /nobreak >nul

echo [*] Starting %TARGET_PKG%...
adb shell !START_CMD!

echo [*] Waiting for process (tight loop)...
set "PID="
:pid_loop_q
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID goto :pid_loop_q

echo [*] PID: !PID! -- attaching agent immediately...
adb shell cmd activity attach-agent %TARGET_PKG% %AGENT_NAME%

echo.
echo [*] Attach command sent. TUI will connect automatically when socket appears.
echo [*] Deferred breakpoints activate when the target class first loads.
goto :eof

REM ---- Sigstop path: fresh start, SIGSTOP on PID, attach, SIGCONT -------------
:sigstop
echo [*] Pre-establishing port forward...
adb forward tcp:12345 localabstract:dexbgd

echo [*] Force-stopping %TARGET_PKG%...
adb shell am force-stop %TARGET_PKG%
timeout /t 1 /nobreak >nul

echo [*] Starting %TARGET_PKG%...
adb shell !START_CMD!

echo [*] Waiting for process (tight loop)...
set "PID="
:pid_loop_s
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID goto :pid_loop_s

echo [*] PID: !PID! -- sending SIGSTOP...
adb shell su -c "kill -STOP !PID!"

echo [*] Attaching agent (SIGCONT briefly to let Binder thread run)...
adb shell su -c "kill -CONT !PID!"
adb shell cmd activity attach-agent %TARGET_PKG% %AGENT_NAME%

echo [*] Polling for agent socket (up to 30s)...
set "SOCKET_READY="
for /l %%j in (1,1,30) do (
    if not defined SOCKET_READY (
        for /f "tokens=*" %%S in ('adb shell grep dexbgd /proc/net/unix 2^>nul') do set "SOCKET_READY=1"
        if not defined SOCKET_READY timeout /t 1 /nobreak >nul
    )
)
if not defined SOCKET_READY (
    echo ERROR: Agent socket @dexbgd not found after 30s
    echo Check: adb logcat -s ArtJitTracer
    exit /b 1
)

echo [*] Socket ready. Freezing app again...
adb shell su -c "kill -STOP !PID!"

echo.
echo [*] App is frozen. TUI will auto-connect and set breakpoints.
echo [*] When ready to resume the app run:
echo     scripts\resume.bat %TARGET_PKG%
goto :eof

REM ---- Ptrace path: inject .so directly via ptrace while process runs --------
:ptrace
set "INJECT_BIN=/data/local/tmp/dexbgd-inject"

echo [*] Pre-establishing port forward...
adb forward tcp:12345 localabstract:dexbgd

echo [*] Force-stopping %TARGET_PKG%...
adb shell am force-stop %TARGET_PKG%
timeout /t 1 /nobreak >nul

echo [*] Starting %TARGET_PKG%...
adb shell !START_CMD!

echo [*] Waiting for process (tight loop)...
set "PID="
:pid_loop_p
for /f "tokens=*" %%P in ('adb shell pidof %TARGET_PKG% 2^>nul') do set "PID=%%P"
if not defined PID goto :pid_loop_p
echo [*] PID: !PID!

echo [*] Injecting agent via ptrace...
adb shell su -c "%INJECT_BIN% !PID! %SO_PATH%"
if errorlevel 1 (
    echo ERROR: inject failed -- see output above
    exit /b 1
)

echo.
echo [*] Done. App is running.
goto :eof
