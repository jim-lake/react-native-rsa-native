package com.example;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiSelector;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import android.content.Context;
import android.content.Intent;

@RunWith(AndroidJUnit4.class)
public class RSATest {

    private UiDevice device;
    private static final String TAG = "RSATest";

    @Before
    public void setUp() {
        Log.d(TAG, "Setting up test");
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
        
        // Launch the app
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Intent intent = context.getPackageManager().getLaunchIntentForPackage("com.example");
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
        context.startActivity(intent);
        
        // Wait for app to launch
        device.waitForIdle(3000);
        Log.d(TAG, "App launched");
    }

    @Test
    public void testRSAFunctionalitySuccess() throws Exception {
        Log.d(TAG, "Starting RSA functionality test");
        
        // Wait for tests to complete (10 seconds max)
        for (int i = 0; i < 10; i++) {
            Log.d(TAG, "Checking for results, attempt " + (i + 1));
            
            // Look for Success text
            UiObject successText = device.findObject(new UiSelector().textContains("Success"));
            if (successText.exists()) {
                Log.d(TAG, "SUCCESS: Found Success status");
                return;
            }
            
            // Check for failure
            UiObject failureText = device.findObject(new UiSelector().textContains("Failure"));
            if (failureText.exists()) {
                Log.d(TAG, "FAILURE: Found Failure status");
                throw new AssertionError("RSA tests failed - found Failure status");
            }
            
            Thread.sleep(1000);
        }
        
        Log.d(TAG, "TIMEOUT: No results found within 10 seconds");
        throw new AssertionError("RSA tests did not complete within 10 seconds");
    }
}
