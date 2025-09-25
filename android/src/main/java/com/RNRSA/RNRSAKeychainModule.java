package com.RNRSA;

import android.os.AsyncTask;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.WritableNativeMap;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class RNRSAKeychainModule extends ReactContextBaseJavaModule {

  private static final String SHA256withRSA = "SHA256withRSA";
  private static final String SHA512withRSA = "SHA512withRSA";
  private static final String SHA1withRSA = "SHA1withRSA";
  private static final String SHA256withECDSA = "SHA256withECDSA";
  private static final String SHA512withECDSA = "SHA512withECDSA";
  private static final String SHA1withECDSA = "SHA1withECDSA";

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
    constants.put(SHA256withECDSA, SHA256withECDSA);
    constants.put(SHA512withECDSA, SHA512withECDSA);
    constants.put(SHA1withECDSA, SHA1withECDSA);
    return constants;
  }

  @ReactMethod
  public void generateKeys(
      final String keyTag,
      final int keySize,
      final boolean synchronizable,
      final String label,
      final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            WritableNativeMap keys = new WritableNativeMap();

            try {
              RSA rsa = new RSA();
              rsa.generate(keyTag, keySize, synchronizable, label, reactContext);
              
              // Return raw base64 PKCS#1 format to match getAllKeys behavior
              keys.putString("public", rsa.getRawPublicKey());
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
  public void generateEC(
      final String keyTag,
      final boolean synchronizable,
      final String label,
      final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(
        new Runnable() {
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
  public void generateEd(
      final String keyTag,
      final boolean synchronizable,
      final String label,
      final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            WritableNativeMap keys = new WritableNativeMap();

            try {
              RSA rsa = new RSA();
              rsa.generateEd(keyTag, synchronizable, label, reactContext);
              keys.putString("public", rsa.getPublicKeyEd(keyTag, reactContext));
              promise.resolve(keys);
            } catch (NoSuchAlgorithmException e) {
              promise.reject("NoSuchAlgorithmException", e.getMessage() != null ? e.getMessage() : "No algorithm error");
            } catch (Exception e) {
              String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
              promise.reject("GenerateEdError", "generateEd failed: " + errorMsg);
            }
          }
        });
  }

  @ReactMethod
  public void generateCSR(
      final String keyTag,
      final String commonName,
      final String withAlgorithm,
      final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(
        new Runnable() {
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
  public void generateCSRWithEC(
      final String cn, final String keyTag, final int keySize, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;

    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            WritableNativeMap keys = new WritableNativeMap();

            try {
              RSA rsa = new RSA();
              rsa.generateCSRWithEC(cn, keyTag, keySize, reactContext);
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
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              // First try to delete from Android KeyStore (RSA/EC keys)
              boolean deletedFromKeyStore = false;
              try {
                RSA rsa = new RSA(keyTag);
                rsa.deletePrivateKey();
                deletedFromKeyStore = true;
              } catch (Exception e) {
                // Key not found in KeyStore, continue to check Ed25519
              }
              
              // Also try to delete from Ed25519 SharedPreferences
              boolean deletedFromEd25519 = false;
              try {
                deletedFromEd25519 = Ed25519Helper.deleteKey(keyTag, reactContext);
              } catch (Exception e) {
                // Key not found in Ed25519 storage
              }
              
              if (deletedFromKeyStore || deletedFromEd25519) {
                promise.resolve(1);
              } else {
                promise.reject("Error", "Key not found: " + keyTag);
              }
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }

  @ReactMethod
  public void encrypt64(final String message, final String keyTag, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
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
  public void decrypt64(final String encodedMessage, final String keyTag, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
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
  public void sign64WithAlgorithm(
      final String message, final String keyTag, final String algorithm, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
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
  public void verify64WithAlgorithm(
      final String signature,
      final String message,
      final String keyTag,
      final String algorithm,
      final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
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
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA(keyTag);
              String publicKey = rsa.getPublicKey();
              if (publicKey != null) {
                WritableNativeMap result = new WritableNativeMap();
                result.putString("public", publicKey);
                promise.resolve(result);
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
  public void getPublicKeyDER(final String keyTag, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA(keyTag);
              String publicKey = rsa.getPublicKeyDER();
              if (publicKey != null) {
                WritableNativeMap result = new WritableNativeMap();
                result.putString("public", publicKey);
                promise.resolve(result);
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
  public void getPublicKeyRSA(final String keyTag, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA(keyTag);
              String publicKey = rsa.getPublicKey(); // This returns PKCS#1 format
              if (publicKey != null) {
                WritableNativeMap result = new WritableNativeMap();
                result.putString("public", publicKey);
                promise.resolve(result);
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
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              WritableNativeArray keysArray = new WritableNativeArray();

              KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
              keyStore.load(null);

              Enumeration<String> aliases = keyStore.aliases();
              while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                try {
                  PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
                  if (privateKey != null) {
                    PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

                    WritableNativeMap keyInfo = new WritableNativeMap();
                    keyInfo.putString("class", "Private");
                    keyInfo.putString("type", privateKey.getAlgorithm());
                    keyInfo.putInt("size", getKeySize(privateKey));
                    
                    // Format public key to match the format returned by generate methods
                    String formattedPublicKey;
                    if (publicKey.getAlgorithm().equals("RSA")) {
                      // For RSA keys, extract PKCS#1 from X.509 DER format and return as raw base64
                      try {
                        RSA rsa = new RSA();
                        byte[] pkcs1PublicKey = rsa.publicKeyToPkcs1(publicKey);
                        formattedPublicKey = android.util.Base64.encodeToString(
                            pkcs1PublicKey, android.util.Base64.NO_WRAP);
                      } catch (Exception e) {
                        // Fallback to X.509 format
                        formattedPublicKey = android.util.Base64.encodeToString(
                            publicKey.getEncoded(), android.util.Base64.NO_WRAP);
                      }
                    } else if (publicKey.getAlgorithm().equals("EC")) {
                      // For EC keys, extract raw uncompressed point to match generateEC behavior
                      try {
                        formattedPublicKey = extractECPublicKeyRaw(publicKey);
                      } catch (Exception e) {
                        // Fallback to X.509 format
                        formattedPublicKey = android.util.Base64.encodeToString(
                            publicKey.getEncoded(), android.util.Base64.NO_WRAP);
                      }
                    } else {
                      // For other keys, use X.509 format
                      formattedPublicKey = android.util.Base64.encodeToString(
                          publicKey.getEncoded(), android.util.Base64.NO_WRAP);
                    }
                    
                    keyInfo.putString("public", formattedPublicKey);
                    keyInfo.putBoolean(
                        "extractable", false); // Android KeyStore keys are non-extractable
                    keyInfo.putString("tag", alias);
                    keyInfo.putString("label", "");
                    keyInfo.putBoolean("syncronizable", false);
                    keyInfo.putString("accessControl", "");

                    keysArray.pushMap(keyInfo);
                  }
                } catch (Exception e) {
                  // Skip keys that can't be accessed
                }
              }

              // Add Ed25519 keys from SharedPreferences
              try {
                java.util.Map<String, String> ed25519Keys = Ed25519Helper.getAllKeys(reactContext);
                for (java.util.Map.Entry<String, String> entry : ed25519Keys.entrySet()) {
                  WritableNativeMap keyInfo = new WritableNativeMap();
                  keyInfo.putString("class", "Private");
                  keyInfo.putString("type", "Ed25519");
                  keyInfo.putInt("size", 256); // Ed25519 is 256-bit
                  keyInfo.putString("public", entry.getValue());
                  keyInfo.putString("publicEd25519", entry.getValue()); // Add publicEd25519 property
                  keyInfo.putBoolean("extractable", false);
                  keyInfo.putString("tag", entry.getKey());
                  keyInfo.putString("label", "");
                  keyInfo.putBoolean("syncronizable", false);
                  keyInfo.putString("accessControl", "");

                  keysArray.pushMap(keyInfo);
                }
              } catch (Exception e) {
                // Skip Ed25519 keys if there's an error
              }

              promise.resolve(keysArray);
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }

  private String extractECPublicKeyRaw(PublicKey publicKey) throws Exception {
    // Get the DER-encoded public key
    byte[] encoded = publicKey.getEncoded();
    
    // Parse the DER structure to extract the raw public key bytes
    // For P-256, the raw public key is 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
    // We need to find the BIT STRING containing the public key
    
    // Simple DER parsing - look for the bit string tag (0x03)
    for (int i = 0; i < encoded.length - 65; i++) {
      if (encoded[i] == 0x03 && encoded[i + 1] == 0x42 && encoded[i + 2] == 0x00 && encoded[i + 3] == 0x04) {
        // Found BIT STRING with length 0x42 (66 bytes), unused bits 0x00, and uncompressed point 0x04
        byte[] rawKey = new byte[65];
        System.arraycopy(encoded, i + 3, rawKey, 0, 65);
        return android.util.Base64.encodeToString(rawKey, android.util.Base64.NO_WRAP);
      }
    }
    
    // Fallback: if we can't parse the DER, return the full encoded key
    return android.util.Base64.encodeToString(encoded, android.util.Base64.NO_WRAP);
  }

  private byte[] convertPublicKeyToPkcs1(PublicKey publicKey) throws IOException {
    try {
      // Use reflection to access the private method from RSA class
      Class<?> rsaClass = RSA.class;
      java.lang.reflect.Method method = rsaClass.getDeclaredMethod("publicKeyToPkcs1", PublicKey.class);
      method.setAccessible(true);
      RSA rsa = new RSA();
      return (byte[]) method.invoke(rsa, publicKey);
    } catch (Exception e) {
      throw new IOException("Failed to convert public key to PKCS#1", e);
    }
  }

  private String convertToPem(String header, byte[] data) {
    try {
      // Use reflection to access the private method from RSA class
      Class<?> rsaClass = RSA.class;
      java.lang.reflect.Method method = rsaClass.getDeclaredMethod("dataToPem", String.class, byte[].class);
      method.setAccessible(true);
      RSA rsa = new RSA();
      return (String) method.invoke(rsa, header, data);
    } catch (Exception e) {
      // Fallback to manual PEM formatting
      String base64 = android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP);
      return "-----BEGIN " + header + "-----\n" + base64 + "\n-----END " + header + "-----\n";
    }
  }

  private int getKeySize(PrivateKey key) {
    if (key instanceof RSAPrivateKey) {
      return ((RSAPrivateKey) key).getModulus().bitLength();
    } else if (key instanceof ECPrivateKey) {
      return 256; // Standard EC key size in Android KeyStore
    }
    return 0;
  }

  @ReactMethod
  public void updatePrivateKey(final String keyTag, final String label, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA();
              boolean success = rsa.updatePrivateKey(keyTag, label, reactContext);
              promise.resolve(success);
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }

  @ReactMethod
  public void deleteAllKeys(final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              int deletedCount = 0;
              
              // Delete all keys from Android KeyStore
              try {
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                
                // Collect aliases first to avoid concurrent modification
                java.util.List<String> aliases = new java.util.ArrayList<>();
                Enumeration<String> aliasEnum = keyStore.aliases();
                while (aliasEnum.hasMoreElements()) {
                  aliases.add(aliasEnum.nextElement());
                }
                
                // Delete each key
                for (String alias : aliases) {
                  try {
                    keyStore.deleteEntry(alias);
                    deletedCount++;
                  } catch (Exception e) {
                    // Skip keys that can't be deleted, continue with others
                  }
                }
              } catch (Exception e) {
                // If KeyStore operations fail, continue with Ed25519 cleanup
              }
              
              // Delete all Ed25519 keys from SharedPreferences
              try {
                int ed25519Deleted = Ed25519Helper.deleteAllKeys(reactContext);
                deletedCount += ed25519Deleted;
              } catch (Exception e) {
                // Skip if there's an error with Ed25519 cleanup
              }
              
              promise.resolve(deletedCount);
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }

  @ReactMethod
  public void signEd(final String message, final String keyTag, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA();
              String signature = rsa.signEd(message, keyTag, reactContext);
              promise.resolve(signature);
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }

  @ReactMethod
  public void verifyEd(final String signature, final String message, final String publicKey, final Promise promise) {
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA();
              boolean verified = rsa.verifyEd(signature, message, publicKey);
              promise.resolve(verified);
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }

  @ReactMethod
  public void getPublicKeyEd(final String keyTag, final Promise promise) {
    final ReactApplicationContext reactContext = this.reactContext;
    AsyncTask.execute(
        new Runnable() {
          @Override
          public void run() {
            try {
              RSA rsa = new RSA();
              String publicKey = rsa.getPublicKeyEd(keyTag, reactContext);
              if (publicKey != null) {
                WritableNativeMap result = new WritableNativeMap();
                result.putString("public", publicKey);
                promise.resolve(result);
              } else {
                promise.reject("Error", "Missing public key for that keyTag");
              }
            } catch (Exception e) {
              promise.reject("Error", e.getMessage());
            }
          }
        });
  }
}
