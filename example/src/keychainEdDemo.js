import { RSAKeychain } from 'react-native-rsa-native';

function uint8ArrayToBase64(uint8Array) {
  let binary = '';
  const len = uint8Array.length;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary);
}

const keychainEdDemo = async () => {
  try {
    console.log('keychainEdDemo start');
    const ED_TAG = 'ed_tag1';
    await RSAKeychain.deletePrivateKey(ED_TAG);

    // Test Ed key generation with synchronizable and label
    const keys = await RSAKeychain.generateEd(ED_TAG, false, 'Test Ed Key');
    console.log('Ed public key:', keys.public);

    // Strict public key format verification for Ed25519
    try {
      // Ed25519 public key from iOS keychain is raw 32-byte format
      const keyData = Uint8Array.from(atob(keys.public.replace(/\s/g, '')), c =>
        c.charCodeAt(0),
      );

      // Ed25519 public key should be exactly 32 bytes
      if (keyData.length !== 32) {
        console.log(
          `Ed25519 public key should be 32 bytes, got ${keyData.length}`,
        );
        return false;
      }

      console.log('Ed25519 public key format validation passed (32 bytes raw)');
    } catch (parseErr) {
      console.log('Ed25519 public key format validation failed:', parseErr);
      return false;
    }

    // Test getPublicKeyEd method
    const publicKeyResult = await RSAKeychain.getPublicKeyEd(ED_TAG);
    console.log('Retrieved Ed public key:', publicKeyResult.public);

    // Verify consistency between generateEd and getPublicKeyEd
    if (keys.public !== publicKeyResult.public) {
      console.log(
        'Ed25519 public key mismatch between generateEd and getPublicKeyEd',
      );
      return false;
    }

    // Test getAllKeys and verify key consistency
    const allKeys = await RSAKeychain.getAllKeys();
    const matchingKey = allKeys.find(key => key.tag === ED_TAG);
    if (!matchingKey) {
      console.log('Ed25519 key not found in getAllKeys');
      return false;
    }

    // For Ed25519 keys, verify both public and publicEd25519 fields
    const allKeysPublicKey = matchingKey.publicEd25519 || matchingKey.public;
    if (allKeysPublicKey !== keys.public) {
      console.log(
        'Ed25519 public key mismatch between generate and getAllKeys',
      );
      console.log('Generate key:', keys.public);
      console.log('getAllKeys key:', allKeysPublicKey);
      return false;
    }
    
    // Verify publicEd25519 property is set correctly for Ed25519 keys
    if (matchingKey.type === 'Ed25519' && !matchingKey.publicEd25519) {
      console.log('Ed25519 key missing publicEd25519 property in getAllKeys');
      return false;
    }
    if (matchingKey.publicEd25519 && matchingKey.publicEd25519 !== keys.public) {
      console.log('Ed25519 publicEd25519 property mismatch in getAllKeys');
      return false;
    }
    
    console.log(
      'Ed25519 key consistency verified between generate and getAllKeys',
    );

    // Test Ed25519 signing
    const message = btoa('Hello Ed25519!'); // Base64 encode the message
    const signature = await RSAKeychain.signEd(message, ED_TAG);
    console.log(
      'Ed signature: (converted from uint8 to b64):',
      uint8ArrayToBase64(signature),
    );

    // Validate Ed25519 signature format - must be exactly 64 bytes, no exceptions
    try {
      // Ed25519 signatures are always exactly 64 bytes (512 bits)
      if (signature.length !== 64) {
        console.log(
          `Ed25519 signature must be exactly 64 bytes, got ${signature.length} bytes`,
        );
        return false;
      }
      // Verify it's a Uint8Array (not base64 string or other format)
      if (!(signature instanceof Uint8Array)) {
        console.log('Ed25519 signature must be Uint8Array format');
        return false;
      }
      console.log('Ed25519 signature format valid (64 bytes)');
    } catch (parseErr) {
      console.log('Ed25519 signature parsing failed:', parseErr);
      return false;
    }

    // Test Ed25519 verification
    const isValid = await RSAKeychain.verifyEd(
      signature,
      message,
      publicKeyResult.public,
    );
    console.log('Ed signature valid:', isValid);

    // Test with invalid signature
    const invalidSignature = btoa('invalid_signature_data');
    const isInvalid = await RSAKeychain.verifyEd(
      invalidSignature,
      message,
      publicKeyResult.public,
    );
    console.log('Invalid Ed signature valid (should be false):', isInvalid);

    const success = await RSAKeychain.deletePrivateKey(ED_TAG);
    console.log('Ed delete success', success);
    return success && isValid && !isInvalid;
  } catch (e) {
    console.log('keychainEdDemo failed:', e);
    return false;
  }
};

export default keychainEdDemo;
