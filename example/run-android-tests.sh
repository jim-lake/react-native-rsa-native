#!/bin/bash

# Change to script directory
cd "$(dirname "$0")"

# Check if Metro bundler is running
if ! pgrep -f "metro" > /dev/null; then
    echo "Starting Metro bundler..."
    npx react-native start > /dev/null 2>&1 &
    METRO_PID=$!
    echo "Metro started with PID: $METRO_PID"
    sleep 5
else
    echo "Metro bundler is already running"
    METRO_PID=""
fi

# Start real-time logcat with line buffering
adb logcat -c
adb logcat -v time | grep --line-buffered -E "(System.out|TestRunner|ReactNativeJS|InstrumentationResultParser)" &
LOGCAT_PID=$!

sleep 1

echo "Running Android instrumentation tests..."
cd android

# Run tests in quiet mode
./gradlew app:connectedAndroidTest --quiet
TEST_EXIT_CODE=$?

# Stop logcat
kill $LOGCAT_PID 2>/dev/null

# Stop Metro if we started it
if [ ! -z "$METRO_PID" ]; then
    echo "Stopping Metro bundler..."
    kill $METRO_PID 2>/dev/null
fi

exit $TEST_EXIT_CODE
