#!/bin/bash

# Change to script directory
cd "$(dirname "$0")"

echo "Running iOS tests on iPhone 16 simulator..."

# Start Metro bundler with client logs to capture console output
npm run start -- --client-logs &
METRO_PID=$!

# Wait longer for Metro to start
sleep 10

# Build and run the app on iPhone 16 simulator
npx react-native run-ios --simulator="iPhone 16" --no-packager &
RN_PID=$!

# Wait much longer for app to build, launch and tests to complete (slow process)
sleep 90

# Stop processes
kill $METRO_PID 2>/dev/null
kill $RN_PID 2>/dev/null

# Terminate the app
xcrun simctl terminate booted org.reactjs.native.example.example 2>/dev/null

echo "iOS tests completed"
