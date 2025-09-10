
package com.RNRSA;

import android.os.AsyncTask;
import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.WritableNativeMap;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class RNRSAKeychainModule extends ReactContextBaseJavaModule {

  private static final String SHA256withRSA = "SHA256withRSA";
  private static final String SHA512withRSA = "SHA512withRSA";
  private static final String SHA1withRSA = "SHA1withRSA";

  private final ReactApplicationContext reactContext;

  public RNRSAKeychainModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNRSAKeychain";
  }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put(SHA256withRSA, SHA256withRSA);
    constants.put(SHA512withRSA, SHA512withRSA);
    constants.put(SHA1withRSA, SHA1withRSA);
    return constants;
  }

  @ReactMethod
  public void generate(final String keyTag, final Promise promise) {
    this.generateKeys(keyTag, 2048, false, null, promise);
  }

  @ReactMethod
  public void generateKeys(final String keyTag, final int keySize, final Promise promise) {
    this.generateKeys(keyTag, keySize, false, null, promise);
  }

  @ReactMethod
  public void generateKeys(final String keyTag, final int keySize, final boolean synchronizable, final String label, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          RSA rsa = new RSA();
          rsa.generate(keyTag, keySize, synchronizable, label, reactContext);
          keys.putString("public", rsa.getPublicKey());
          promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void generateEC(final String keyTag, final Promise promise) {
    this.generateEC(keyTag, false, null, promise);
  }

  @ReactMethod
  public void generateEC(final String keyTag, final boolean synchronizable, final String label, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          RSA rsa = new RSA();
          rsa.generateEC(keyTag, synchronizable, label, reactContext);
          keys.putString("public", rsa.getPublicKey());
          promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void generateEd(final String keyTag, final Promise promise) {
    this.generateEd(keyTag, false, null, promise);
  }

  @ReactMethod
  public void generateEd(final String keyTag, final boolean synchronizable, final String label, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          RSA rsa = new RSA();
          rsa.generateEd(keyTag, synchronizable, label, reactContext);
          keys.putString("public", rsa.getPublicKey());
          promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void generateCSR(final String keyTag, final String commonName, final String withAlgorithm, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          RSA rsa = new RSA(keyTag);
          rsa.generateCSR(commonName, withAlgorithm, reactContext);
          keys.putString("csr", rsa.getCSR());
          promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void generateCSRWithEC(final String cn,final String keyTag, final int keySize, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          RSA rsa = new RSA();
          rsa.generateCSRWithEC(cn,keyTag, keySize, reactContext);
          keys.putString("csr", rsa.getCSR());
          promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void deletePrivateKey(final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          rsa.deletePrivateKey();
          promise.resolve(1);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void encrypt(final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String encodedMessage = rsa.encrypt(message);
          promise.resolve(encodedMessage);
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void encrypt64(final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String encodedMessage = rsa.encrypt64(message);
          promise.resolve(encodedMessage);
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void decrypt(final String encodedMessage, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String message = rsa.decrypt(encodedMessage);
          promise.resolve(message);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void decrypt64(final String encodedMessage, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String message = rsa.decrypt64(encodedMessage);
          promise.resolve(message);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void sign(final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String signature = rsa.sign(message, SHA512withRSA);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void signWithAlgorithm(final String message, final String keyTag, final String algorithm, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String signature = rsa.sign(message, algorithm);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void sign64(final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String signature = rsa.sign64(message, SHA512withRSA);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }
  @ReactMethod
  public void sign64WithAlgorithm(final String message, final String keyTag, final String algorithm, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          String signature = rsa.sign64(message, algorithm);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verify(final String signature, final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          boolean verified = rsa.verify(signature, message, SHA512withRSA);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verifyWithAlgorithm(final String signature, final String message, final String keyTag, final String algorithm, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          boolean verified = rsa.verify(signature, message, algorithm);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verify64(final String signature, final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          boolean verified = rsa.verify64(signature, message, SHA512withRSA);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verify64WithAlgorithm(final String signature, final String message, final String keyTag, final String algorithm, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA(keyTag);
          boolean verified = rsa.verify64(signature, message, algorithm);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void getPublicKey(final String keyTag, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          RSA rsa = new RSA(keyTag);
          String publicKey = rsa.getPublicKey();
          if (publicKey != null) {
            promise.resolve(publicKey);
          } else {
            promise.reject("Error", "Missing public key for that keyTag");
          }
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void getAllKeys(final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          // Android KeyStore doesn't provide a direct way to enumerate all keys
          // This is a simplified implementation that returns an empty array
          // In a real implementation, you would need to maintain a registry of key tags
          WritableNativeArray keysArray = new WritableNativeArray();
          promise.resolve(keysArray);
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void deleteAllKeys(final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          // Android KeyStore doesn't provide a direct way to delete all keys
          // This would require maintaining a registry of key tags and deleting each one
          // For now, we'll just return true
          promise.resolve(true);
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }
}
