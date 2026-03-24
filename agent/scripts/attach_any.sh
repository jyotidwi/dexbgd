#!/bin/bash
# attach_any.sh -- Attach the dexbgd agent to a target app
#
# Improvements over attach.sh:
#   - Auto-discovers the launcher activity (no hardcoded .MainActivity)
#   - Handles split APKs (pm path returns multiple lines)
#   - Uses monkey to launch (works with alias activities)
#
# Usage:
#   ./scripts/attach_any.sh <package_name>             # normal attach (app must be running)
#   ./scripts/attach_any.sh <package_name> --quick     # force-stop, fresh start, attach ASAP
#   ./scripts/attach_any.sh <package_name> --sigstop   # like --quick but SIGSTOP on PID appearance
#                                                       # so agent attaches while app is frozen (root)
#   ./scripts/attach_any.sh <package_name> --ptrace    # inject via ptrace (no repackaging, root)
#
# NOTE: --quick and --sigstop use "cmd activity attach-agent" which requires android:debuggable=true.
#       They only work with repackaged APKs (Option A). For production apps use --ptrace instead.
#
# NOTE: --suspended (am start -D) does NOT work on Android 14 -- JDWP freezes the
#       Binder thread so attach-agent is never processed.
#       Use --sigstop instead.

set -uo pipefail

TARGET_PKG="${1:-com.test.profiletest}"
MODE="${2:-}"
AGENT_NAME="libart_jit_tracer.so"

# Verify package is installed
if ! adb shell pm path "$TARGET_PKG" >/dev/null 2>&1; then
    echo "ERROR: Package $TARGET_PKG not found on device"
    exit 1
fi
echo "[*] Package: $TARGET_PKG"

# Resolve launcher activity (info only -- we use monkey to actually launch).
# tr -d '\r' uses single quotes so bash passes \r literally to tr (carriage return),
# not as escaped-r which would strip all 'r' characters.
MAIN_ACTIVITY=$(adb shell "cmd package resolve-activity --brief -c android.intent.category.LAUNCHER $TARGET_PKG 2>/dev/null | grep / | tail -1 | tr -d '\r'" 2>/dev/null || true)
if [ -n "$MAIN_ACTIVITY" ]; then
    echo "[*] Launcher: $MAIN_ACTIVITY"
else
    echo "[*] Could not resolve launcher activity"
fi

# Use monkey to launch -- handles alias activities, split APKs, non-standard launchers.
# Equivalent to tapping the app icon.
start_app() {
    adb shell "monkey -p $TARGET_PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 || true
}

# Derive .so path from first pm path line only (handles split APKs).
#   package:/data/app/~~HASH/com.pkg-1/base.apk  (first line)
#   ->  /data/app/~~HASH/com.pkg-1/lib/arm64/libart_jit_tracer.so
SO_PATH=$(adb shell "d=\$(pm path $TARGET_PKG | head -n1 | cut -d: -f2 | tr -d '\r'); echo \$(dirname \$d)/lib/arm64/$AGENT_NAME" 2>/dev/null | tr -d '\r')
if [ -z "$SO_PATH" ]; then
    echo "ERROR: Could not resolve .so path for $TARGET_PKG"
    exit 1
fi
echo "[*] .so path: $SO_PATH"

# ---- Normal path: ensure app is running, then attach -------------------------
if [ "$MODE" != "--quick" ] && [ "$MODE" != "--sigstop" ] && [ "$MODE" != "--ptrace" ]; then
    PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
    if [ -z "$PID" ]; then
        echo "[*] App not running, starting it..."
        start_app
        sleep 2
        PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
        if [ -z "$PID" ]; then
            echo "ERROR: Failed to start $TARGET_PKG"
            exit 1
        fi
    fi
    echo "[*] PID: $PID"
    echo "[*] Attaching agent..."
    adb shell cmd activity attach-agent "$TARGET_PKG" "$AGENT_NAME"
    echo "[*] Agent attached."
    exit 0
fi

# ---- Quick path: fresh start, attach as fast as possible --------------------
if [ "$MODE" = "--quick" ]; then
    echo "[*] Pre-establishing port forward..."
    adb forward tcp:12345 localabstract:dexbgd

    echo "[*] Force-stopping $TARGET_PKG..."
    adb shell am force-stop "$TARGET_PKG"
    sleep 1

    echo "[*] Starting $TARGET_PKG..."
    start_app

    echo "[*] Waiting for process (tight loop)..."
    PID=""
    while [ -z "$PID" ]; do
        PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
    done

    echo "[*] PID: $PID -- attaching agent immediately..."
    adb shell cmd activity attach-agent "$TARGET_PKG" "$AGENT_NAME"

    echo ""
    echo "[*] Attach command sent. TUI will connect automatically when socket appears."
    echo "[*] Deferred breakpoints activate when the target class first loads."
    exit 0
fi

# ---- Sigstop path: fresh start, SIGSTOP on PID, attach, SIGCONT -------------
if [ "$MODE" = "--sigstop" ]; then
    echo "[*] Pre-establishing port forward..."
    adb forward tcp:12345 localabstract:dexbgd

    echo "[*] Force-stopping $TARGET_PKG..."
    adb shell am force-stop "$TARGET_PKG"
    sleep 1

    echo "[*] Starting $TARGET_PKG..."
    start_app

    echo "[*] Waiting for process (tight loop)..."
    PID=""
    while [ -z "$PID" ]; do
        PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
    done

    echo "[*] PID: $PID -- sending SIGSTOP..."
    adb shell su -c "kill -STOP $PID"

    echo "[*] Attaching agent (SIGCONT briefly to let Binder thread run)..."
    adb shell su -c "kill -CONT $PID"
    adb shell cmd activity attach-agent "$TARGET_PKG" "$AGENT_NAME"

    echo "[*] Polling for agent socket (up to 30s)..."
    SOCKET_READY=""
    for _ in $(seq 1 30); do
        if adb shell grep -q dexbgd /proc/net/unix 2>/dev/null; then
            SOCKET_READY=1
            break
        fi
        sleep 1
    done
    if [ -z "$SOCKET_READY" ]; then
        echo "ERROR: Agent socket @dexbgd not found after 30s"
        echo "Check: adb logcat -s ArtJitTracer"
        exit 1
    fi

    echo "[*] Socket ready. Freezing app again..."
    adb shell su -c "kill -STOP $PID"

    echo ""
    echo "[*] App is frozen. TUI will auto-connect and set breakpoints."
    echo "[*] When ready to resume the app run:"
    echo "    ./scripts/resume.sh $TARGET_PKG"
    exit 0
fi

# ---- Ptrace path: inject .so directly via ptrace while process runs ---------
if [ "$MODE" = "--ptrace" ]; then
    INJECT_BIN="/data/local/tmp/dexbgd-inject"

    echo "[*] Pre-establishing port forward..."
    adb forward tcp:12345 localabstract:dexbgd

    echo "[*] Force-stopping $TARGET_PKG..."
    adb shell am force-stop "$TARGET_PKG"
    sleep 1

    echo "[*] Starting $TARGET_PKG..."
    start_app

    echo "[*] Waiting for process (tight loop)..."
    PID=""
    while [ -z "$PID" ]; do
        PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
    done
    echo "[*] PID: $PID"

    echo "[*] Injecting agent via ptrace..."
    if ! adb shell su -c "$INJECT_BIN $PID $SO_PATH"; then
        echo "ERROR: inject failed -- see output above"
        exit 1
    fi

    echo ""
    echo "[*] Done. App is running."
    exit 0
fi

echo "ERROR: Unknown mode: $MODE"
echo "Usage: $0 <package> [--quick|--sigstop|--ptrace]"
exit 1
