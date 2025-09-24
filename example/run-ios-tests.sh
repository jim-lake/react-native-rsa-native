#!/bin/bash

# Change to script directory
cd "$(dirname "$0")"

echo "Running iOS tests on iPhone 16 simulator..."

# Kill any existing Metro/React Native processes
pkill -f "react-native start" 2>/dev/null || true
pkill -f "metro" 2>/dev/null || true
lsof -ti:8081 | xargs kill -9 2>/dev/null || true
sleep 2

# Start Metro bundler with client logs and capture output
npm run start -- --client-logs > metro.log 2>&1 &
METRO_PID=$!

# Wait for Metro to start
sleep 10

# Build and run the app
npx react-native run-ios --simulator="iPhone 16" --no-packager &
RN_PID=$!

# Monitor Metro log for test completion
echo "Waiting for tests to complete..."
tail -f metro.log &
TAIL_PID=$!

# Wait for either "Test failed" or completion of all tests
while true; do
    if grep -q "ALL_TESTS_COMPLETED" metro.log 2>/dev/null; then
        echo "Tests completed!"
        break
    fi
    sleep 2
done

# Stop all processes
kill $TAIL_PID 2>/dev/null
kill $METRO_PID 2>/dev/null
kill $RN_PID 2>/dev/null

# Terminate the app
xcrun simctl terminate booted org.reactjs.native.example.example 2>/dev/null

# Final cleanup
pkill -f "react-native start" 2>/dev/null || true
pkill -f "metro" 2>/dev/null || true
rm -f metro.log

echo "iOS tests completed"
