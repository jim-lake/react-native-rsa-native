#!/bin/bash

# Change to script directory
cd "$(dirname "$0")"

echo "Running iOS tests on iPhone 16 simulator..."

# Check if Metro is already running on port 8081
if lsof -ti:8081 > /dev/null 2>&1; then
    echo "Metro is already running on port 8081, using existing instance"
    METRO_PID=""
else
    echo "Starting new Metro instance"
    METRO_PID=""
fi

# Create temp files in TMPDIR
METRO_LOG="$TMPDIR/metro.log"
BUILD_LOG="$TMPDIR/build.log"

# Start Metro bundler only if not already running
if [ -z "$METRO_PID" ] && ! lsof -ti:8081 > /dev/null 2>&1; then
    npm run start -- --client-logs > "$METRO_LOG" 2>&1 &
    METRO_PID=$!
    echo "Started new Metro instance with PID: $METRO_PID"
    sleep 10
else
    echo "Using existing Metro instance"
    # Create empty log file for consistency
    touch "$METRO_LOG"
    sleep 2
fi

# Build and run the app, capture build output
echo "Building and launching app..."
npx react-native run-ios --simulator="iPhone 16" --no-packager > "$BUILD_LOG" 2>&1 &
RN_PID=$!

# Wait for build to complete
wait $RN_PID
BUILD_EXIT_CODE=$?

if [ $BUILD_EXIT_CODE -ne 0 ]; then
    echo "Build failed! Output:"
    cat "$BUILD_LOG"
    kill $METRO_PID 2>/dev/null
    rm -f "$METRO_LOG" "$BUILD_LOG"
    exit 1
fi

echo "Build successful, running tests..."

# Monitor Metro log for test completion
tail -f "$METRO_LOG" &
TAIL_PID=$!

# Wait for either "Test failed" or completion of all tests
while true; do
    if grep -q "ALL_TESTS_COMPLETED" "$METRO_LOG" 2>/dev/null; then
        echo "Tests completed!"
        break
    fi
    sleep 2
done

# Stop processes we started
kill $TAIL_PID 2>/dev/null

# Only kill Metro if we started it
if [ ! -z "$METRO_PID" ]; then
    echo "Stopping Metro instance we started..."
    kill $METRO_PID 2>/dev/null
fi

# Terminate the app
xcrun simctl terminate booted org.reactjs.native.example.example 2>/dev/null

# Clean up temp files
rm -f "$METRO_LOG" "$BUILD_LOG"

echo "iOS tests completed"
