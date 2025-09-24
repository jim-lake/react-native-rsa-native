package com.RNRSA;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public class Ed25519 {
    
    public static byte[] publicKeyFromPrivateKey(byte[] privateKey) {
        try {
            Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(privateKey, 0);
            Ed25519PublicKeyParameters publicKeyParams = privateKeyParams.generatePublicKey();
            return publicKeyParams.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive public key", e);
        }
    }
    
    public static byte[] sign(byte[] message, byte[] privateKey) {
        try {
            Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(privateKey, 0);
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, privateKeyParams);
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign message", e);
        }
    }
    
    public static boolean verify(byte[] signature, byte[] message, byte[] publicKey) {
        try {
            if (signature == null || message == null || publicKey == null) {
                return false;
            }
            
            Ed25519PublicKeyParameters publicKeyParams = new Ed25519PublicKeyParameters(publicKey, 0);
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, publicKeyParams);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
