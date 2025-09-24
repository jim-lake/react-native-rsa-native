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
    
    private static SharedPreferences getKeysPrefs(Context context) throws GeneralSecurityException, IOException {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();
            
        return EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }
    
    private static SharedPreferences getLabelsPrefs(Context context) throws GeneralSecurityException, IOException {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();
            
        return EncryptedSharedPreferences.create(
            context,
            LABELS_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
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
    
    public static boolean updateLabel(String keyTag, String label, Context context) throws Exception {
        SharedPreferences labelsPrefs = getLabelsPrefs(context);
        labelsPrefs.edit().putString(keyTag, label).apply();
        return true;
    }
}
