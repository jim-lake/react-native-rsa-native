import { RSAKeychain } from 'react-native-rsa-native';

let secret = 'secret message';

const keychainDemo = async () => {
  try {
    console.log('keychainDemo start');
    const RSA_TAG = 'rsa_tag3';
    await RSAKeychain.deleteAllKeys();

    // Test with synchronizable and label parameters
    const keys = await RSAKeychain.generate(RSA_TAG, true, 'Test RSA Key');
    console.log(keys.public);

    console.log('all keys:', await RSAKeychain.getAllKeys());

    const encodedMessage = await RSAKeychain.encrypt64(btoa(secret), RSA_TAG);
    console.log('encodedMessage:', encodedMessage);
    const message = atob(await RSAKeychain.decrypt64(encodedMessage, RSA_TAG));
    console.log('message:', message);
    const signature = await RSAKeychain.sign64(btoa(secret), RSA_TAG);
    console.log('signature', signature);

    // Validate signature format - RSA signatures are raw bytes, not ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // RSA signatures should be exactly the key size in bytes (2048 bits = 256 bytes)
      if (sigData.length === 256) {
        console.log(
          'Keychain signature format valid (256 bytes for 2048-bit key)',
        );
      } else {
        console.log(
          `Unexpected keychain signature length: ${sigData.length} bytes`,
        );
        return false;
      }
    } catch (parseErr) {
      console.log('Keychain signature parsing failed:', parseErr);
      return false;
    }

    const valid = await RSAKeychain.verify64(signature, btoa(secret), RSA_TAG);
    console.log('verified', valid);
    if (!valid) {
      return false;
    }

    const invalid = await RSAKeychain.verify64(
      signature,
      btoa('wrong message'),
      RSA_TAG,
    );
    console.log('invalid:', invalid);
    if (invalid) {
      return false;
    }

    // Test sign (non-64 version) - signature is already base64, don't encode it again
    const signature2 = await RSAKeychain.sign(secret, RSA_TAG);
    console.log('sign (non-64) signature:', signature2);
    // Use verify64 with the signature as-is and base64-encoded data
    const valid2 = await RSAKeychain.verify64(signature2, btoa(secret), RSA_TAG);
    console.log('sign (non-64) verified:', valid2);
    if (!valid2) {
      return false;
    }

    // Test signWithAlgorithm (non-64 version) with SHA256withRSA
    const signature3 = await RSAKeychain.signWithAlgorithm(secret, RSA_TAG, 'SHA256withRSA');
    console.log('signWithAlgorithm (SHA256) signature:', signature3);
    // Use verify64WithAlgorithm with the signature as-is and base64-encoded data
    const valid3 = await RSAKeychain.verify64WithAlgorithm(signature3, btoa(secret), RSA_TAG, 'SHA256withRSA');
    console.log('signWithAlgorithm (SHA256) verified:', valid3);
    if (!valid3) {
      return false;
    }

    // Test sign64WithAlgorithm with SHA256withRSA
    const signature4 = await RSAKeychain.sign64WithAlgorithm(btoa(secret), RSA_TAG, 'SHA256withRSA');
    console.log('sign64WithAlgorithm (SHA256) signature:', signature4);
    const valid4 = await RSAKeychain.verify64WithAlgorithm(signature4, btoa(secret), RSA_TAG, 'SHA256withRSA');
    console.log('sign64WithAlgorithm (SHA256) verified:', valid4);
    if (!valid4) {
      return false;
    }

    // Test verify (non-64 version) - sign returns base64, verify expects raw signature
    const rawSignature2 = Uint8Array.from(atob(signature2), c => c.charCodeAt(0));
    const valid5 = await RSAKeychain.verify(rawSignature2, secret, RSA_TAG);
    console.log('verify (non-64) verified:', valid5);
    if (!valid5) {
      return false;
    }

    // Test verifyWithAlgorithm (non-64 version) - signWithAlgorithm returns base64, verify expects raw signature
    const rawSignature3 = Uint8Array.from(atob(signature3), c => c.charCodeAt(0));
    const valid6 = await RSAKeychain.verifyWithAlgorithm(rawSignature3, secret, RSA_TAG, 'SHA256withRSA');
    console.log('verifyWithAlgorithm (non-64) verified:', valid6);
    if (!valid6) {
      return false;
    }

    // Test with SHA1withRSA algorithm
    const signature7 = await RSAKeychain.signWithAlgorithm(secret, RSA_TAG, 'SHA1withRSA');
    console.log('signWithAlgorithm (SHA1) signature:', signature7);
    const rawSignature7 = Uint8Array.from(atob(signature7), c => c.charCodeAt(0));
    const valid7 = await RSAKeychain.verifyWithAlgorithm(rawSignature7, secret, RSA_TAG, 'SHA1withRSA');
    console.log('signWithAlgorithm (SHA1) verified:', valid7);
    if (!valid7) {
      return false;
    }

    // Test with SHA512withRSA algorithm explicitly
    const signature8 = await RSAKeychain.signWithAlgorithm(secret, RSA_TAG, 'SHA512withRSA');
    console.log('signWithAlgorithm (SHA512) signature:', signature8);
    const rawSignature8 = Uint8Array.from(atob(signature8), c => c.charCodeAt(0));
    const valid8 = await RSAKeychain.verifyWithAlgorithm(rawSignature8, secret, RSA_TAG, 'SHA512withRSA');
    console.log('signWithAlgorithm (SHA512) verified:', valid8);
    if (!valid8) {
      return false;
    }

    // Test sign64WithAlgorithm with SHA1withRSA
    const signature9 = await RSAKeychain.sign64WithAlgorithm(btoa(secret), RSA_TAG, 'SHA1withRSA');
    console.log('sign64WithAlgorithm (SHA1) signature:', signature9);
    const valid9 = await RSAKeychain.verify64WithAlgorithm(signature9, btoa(secret), RSA_TAG, 'SHA1withRSA');
    console.log('sign64WithAlgorithm (SHA1) verified:', valid9);
    if (!valid9) {
      return false;
    }

    // Test sign64WithAlgorithm with SHA512withRSA
    const signature10 = await RSAKeychain.sign64WithAlgorithm(btoa(secret), RSA_TAG, 'SHA512withRSA');
    console.log('sign64WithAlgorithm (SHA512) signature:', signature10);
    const valid10 = await RSAKeychain.verify64WithAlgorithm(signature10, btoa(secret), RSA_TAG, 'SHA512withRSA');
    console.log('sign64WithAlgorithm (SHA512) verified:', valid10);
    if (!valid10) {
      return false;
    }

    // Test cross-verification: sign64 with verify64WithAlgorithm (default SHA512)
    const valid11 = await RSAKeychain.verify64WithAlgorithm(signature, btoa(secret), RSA_TAG, 'SHA512withRSA');
    console.log('cross-verify sign64 with verify64WithAlgorithm:', valid11);
    if (!valid11) {
      return false;
    }

    // Test cross-verification: sign with verify64 (sign uses SHA512 default, verify64 uses SHA512 default)
    const valid12 = await RSAKeychain.verify64(signature2, btoa(secret), RSA_TAG);
    console.log('cross-verify sign with verify64:', valid12);
    if (!valid12) {
      return false;
    }

    const allKeys = await RSAKeychain.getAllKeys();
    console.log('All keys:', allKeys);

    const success = await RSAKeychain.deletePrivateKey(RSA_TAG);
    console.log('delete success', success);
    return message === secret && valid && success;
  } catch (e) {
    console.log('keychainDemo failed:', e);
    return false;
  }
};

export default keychainDemo;
