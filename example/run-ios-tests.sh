#!/bin/bash

# Change to script directory
cd "$(dirname "$0")"

echo "Running iOS tests on iPhone 16 simulator..."

# Kill any existing Metro/React Native processes
pkill -f "react-native start" 2>/dev/null || true
pkill -f "metro" 2>/dev/null || true
lsof -ti:8081 | xargs kill -9 2>/dev/null || true
sleep 2

# Create temp files in TMPDIR
METRO_LOG="$TMPDIR/metro.log"
BUILD_LOG="$TMPDIR/build.log"

# Start Metro bundler with client logs and capture output
npm run start -- --client-logs > "$METRO_LOG" 2>&1 &
METRO_PID=$!

# Wait for Metro to start
sleep 10

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

# Stop all processes
kill $TAIL_PID 2>/dev/null
kill $METRO_PID 2>/dev/null

# Terminate the app
xcrun simctl terminate booted org.reactjs.native.example.example 2>/dev/null

# Final cleanup
pkill -f "react-native start" 2>/dev/null || true
pkill -f "metro" 2>/dev/null || true
rm -f "$METRO_LOG" "$BUILD_LOG"

echo "iOS tests completed"
