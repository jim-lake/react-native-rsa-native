#!/bin/bash

# Change to script directory
cd "$(dirname "$0")"

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

exit $TEST_EXIT_CODE
