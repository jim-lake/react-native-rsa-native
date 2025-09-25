package com.RNRSA;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.io.IOException;

public class Ed25519Helper {
    private static final String PREFS_NAME = "ed25519_keys";
    private static final String LABELS_PREFS_NAME = "ed25519_labels";
    
    private static SharedPreferences keysPrefsInstance = null;
    private static SharedPreferences labelsPrefsInstance = null;
    
    private static synchronized SharedPreferences getKeysPrefs(Context context) throws GeneralSecurityException, IOException {
        if (keysPrefsInstance == null) {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            
            keysPrefsInstance = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        }
        return keysPrefsInstance;
    }
    
    private static synchronized SharedPreferences getLabelsPrefs(Context context) throws GeneralSecurityException, IOException {
        if (labelsPrefsInstance == null) {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            
            labelsPrefsInstance = EncryptedSharedPreferences.create(
                context,
                LABELS_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        }
        return labelsPrefsInstance;
    }
    
    public static String generateEd25519KeyPair(String keyTag, String label, Context context) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] privateKey = new byte[32];
        random.nextBytes(privateKey);
        
        byte[] publicKey = Ed25519.publicKeyFromPrivateKey(privateKey);
        
        SharedPreferences keysPrefs = getKeysPrefs(context);
        SharedPreferences labelsPrefs = getLabelsPrefs(context);
        
        keysPrefs.edit()
            .putString(keyTag + "_private", Base64.encodeToString(privateKey, Base64.NO_WRAP))
            .putString(keyTag + "_public", Base64.encodeToString(publicKey, Base64.NO_WRAP))
            .apply();
            
        if (label != null && !label.isEmpty()) {
            labelsPrefs.edit().putString(keyTag, label).apply();
        }
        
        return Base64.encodeToString(publicKey, Base64.NO_WRAP);
    }
    
    public static String getPublicKey(String keyTag, Context context) throws Exception {
        SharedPreferences prefs = getKeysPrefs(context);
        return prefs.getString(keyTag + "_public", null);
    }
    
    public static String sign(String message, String keyTag, Context context) throws Exception {
        SharedPreferences prefs = getKeysPrefs(context);
        String privateKeyB64 = prefs.getString(keyTag + "_private", null);
        if (privateKeyB64 == null) {
            throw new Exception("Private key not found for tag: " + keyTag);
        }
        
        byte[] privateKey = Base64.decode(privateKeyB64, Base64.NO_WRAP);
        byte[] messageBytes = Base64.decode(message, Base64.NO_WRAP);
        byte[] signature = Ed25519.sign(messageBytes, privateKey);
        
        return Base64.encodeToString(signature, Base64.NO_WRAP);
    }
    
    public static boolean verify(String signature, String message, String publicKey) throws Exception {
        byte[] signatureBytes = Base64.decode(signature, Base64.NO_WRAP);
        byte[] messageBytes = Base64.decode(message, Base64.NO_WRAP);
        byte[] publicKeyBytes = Base64.decode(publicKey, Base64.NO_WRAP);
        
        return Ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    }
    

    
    public static java.util.Map<String, String> getAllKeys(Context context) throws Exception {
        SharedPreferences keysPrefs = getKeysPrefs(context);
        SharedPreferences labelsPrefs = getLabelsPrefs(context);
        java.util.Map<String, String> result = new java.util.HashMap<>();
        
        java.util.Map<String, ?> allKeys = keysPrefs.getAll();
        for (String key : allKeys.keySet()) {
            if (key.endsWith("_public")) {
                String keyTag = key.substring(0, key.length() - "_public".length());
                String publicKey = (String) allKeys.get(key);
                String label = labelsPrefs.getString(keyTag, "");
                result.put(keyTag, publicKey);
            }
        }
        
        return result;
    }

    public static boolean deleteKey(String keyTag, Context context) throws Exception {
        SharedPreferences keysPrefs = getKeysPrefs(context);
        SharedPreferences labelsPrefs = getLabelsPrefs(context);
        
        keysPrefs.edit()
            .remove(keyTag + "_private")
            .remove(keyTag + "_public")
            .apply();
            
        labelsPrefs.edit().remove(keyTag).apply();
        
        return true;
    }
    
    public static int deleteAllKeys(Context context) throws Exception {
        SharedPreferences keysPrefs = getKeysPrefs(context);
        SharedPreferences labelsPrefs = getLabelsPrefs(context);
        
        java.util.Map<String, ?> allKeys = keysPrefs.getAll();
        java.util.Set<String> keyTags = new java.util.HashSet<>();
        
        // Collect unique key tags (each key has _private and _public entries)
        for (String key : allKeys.keySet()) {
            if (key.endsWith("_public")) {
                String keyTag = key.substring(0, key.length() - "_public".length());
                keyTags.add(keyTag);
            }
        }
        
        // Delete each key individually to avoid corrupting EncryptedSharedPreferences
        SharedPreferences.Editor keysEditor = keysPrefs.edit();
        SharedPreferences.Editor labelsEditor = labelsPrefs.edit();
        
        for (String keyTag : keyTags) {
            keysEditor.remove(keyTag + "_private");
            keysEditor.remove(keyTag + "_public");
            labelsEditor.remove(keyTag);
        }
        
        keysEditor.apply();
        labelsEditor.apply();
        
        return keyTags.size();
    }
    
    public static boolean updateLabel(String keyTag, String label, Context context) throws Exception {
        SharedPreferences labelsPrefs = getLabelsPrefs(context);
        labelsPrefs.edit().putString(keyTag, label).apply();
        return true;
    }
}
