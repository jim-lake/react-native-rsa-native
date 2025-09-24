package com.RNRSA;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Ed25519 {
    
    // Simple Ed25519 implementation using basic crypto operations
    // Note: This is a minimal implementation for compatibility
    // In production, use a proper Ed25519 library
    
    public static byte[] publicKeyFromPrivateKey(byte[] privateKey) {
        // For now, return a derived public key (simplified)
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(privateKey);
            // Take first 32 bytes as public key (simplified approach)
            return Arrays.copyOf(hash, 32);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive public key", e);
        }
    }
    
    public static byte[] sign(byte[] message, byte[] privateKey) {
        // Simplified signing - in production use proper Ed25519
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(privateKey);
            digest.update(message);
            byte[] hash = digest.digest();
            // Return 64-byte signature (simplified)
            byte[] signature = new byte[64];
            System.arraycopy(hash, 0, signature, 0, 32);
            System.arraycopy(hash, 0, signature, 32, 32);
            return signature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign message", e);
        }
    }
    
    public static boolean verify(byte[] signature, byte[] message, byte[] publicKey) {
        // Simplified verification - in production use proper Ed25519
        try {
            // Derive expected public key from message and signature
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Arrays.copyOf(signature, 32)); // Use first 32 bytes as "private key"
            digest.update(message);
            byte[] expectedHash = digest.digest();
            byte[] expectedPublicKey = Arrays.copyOf(expectedHash, 32);
            
            return Arrays.equals(publicKey, expectedPublicKey);
        } catch (Exception e) {
            return false;
        }
    }
}
