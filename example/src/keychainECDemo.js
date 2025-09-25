import { RSAKeychain } from 'react-native-rsa-native';

const keychainECDemo = async () => {
  try {
    console.log('keychainECDemo start');
    const EC_TAG = 'ec_tag1';
    await RSAKeychain.deletePrivateKey(EC_TAG);

    // Test EC key generation with synchronizable and label
    const keys = await RSAKeychain.generateEC(EC_TAG, false, 'Test EC Key');
    console.log('EC public key:', keys.public);

    // Strict public key format verification for EC
    try {
      // EC public key from iOS keychain is raw uncompressed format (65 bytes for P-256)
      const keyData = Uint8Array.from(atob(keys.public.replace(/\s/g, '')), c =>
        c.charCodeAt(0),
      );

      // P-256 uncompressed public key: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes total
      if (keyData.length !== 65) {
        console.log(
          `EC public key should be 65 bytes (uncompressed P-256), got ${keyData.length}`,
        );
        return false;
      }

      // Must start with 0x04 (uncompressed point indicator)
      if (keyData[0] !== 0x04) {
        console.log(
          `EC public key must start with 0x04 (uncompressed), got 0x${keyData[0].toString(
            16,
          )}`,
        );
        return false;
      }

      console.log(
        'EC public key format validation passed (65 bytes uncompressed P-256)',
      );
    } catch (parseErr) {
      console.log('EC public key format validation failed:', parseErr);
      return false;
    }

    // Test getAllKeys and verify key consistency
    const allKeys = await RSAKeychain.getAllKeys();
    const matchingKey = allKeys.find(key => key.tag === EC_TAG);
    if (!matchingKey) {
      console.log('EC key not found in getAllKeys');
      return false;
    }
    if (matchingKey.public !== keys.public) {
      console.log('EC public key mismatch between generate and getAllKeys');
      return false;
    }
    console.log('EC key consistency verified between generate and getAllKeys');

    // Test EC signing and verification
    const message = 'test message for EC';
    const signature = await RSAKeychain.signWithAlgorithm(
      message,
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('EC signature:', signature);

    // Validate EC signature format - must be exactly DER-encoded ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // DER-encoded ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }
      // Must start with 0x30 (SEQUENCE tag)
      if (sigData[0] !== 0x30) {
        console.log('EC signature must start with DER SEQUENCE tag (0x30)');
        return false;
      }
      // Length must be exactly what DER specifies (no padding, no truncation)
      const derLength = sigData[1];
      if (sigData.length !== derLength + 2) {
        console.log(
          `EC signature DER length mismatch: expected ${derLength + 2}, got ${
            sigData.length
          }`,
        );
        return false;
      }
      // For P-256, typical range is 68-72 bytes, but must be exact DER
      if (sigData.length < 68 || sigData.length > 72) {
        console.log(
          `EC signature length ${sigData.length} outside valid P-256 DER range (68-72)`,
        );
        return false;
      }
      console.log(
        `EC signature format valid (${sigData.length} bytes DER-encoded)`,
      );
    } catch (parseErr) {
      console.log('EC signature parsing failed:', parseErr);
      return false;
    }

    const isValid = await RSAKeychain.verifyWithAlgorithm(
      signature,
      message,
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('EC signature valid:', isValid);

    if (!isValid) {
      return false;
    }
    // Test negative verification for EC
    const bad_is_valid = await RSAKeychain.verifyWithAlgorithm(
      signature,
      'wrong message',
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('Wrong message verify:', bad_is_valid);
    if (bad_is_valid) {
      return false;
    }

    const success = await RSAKeychain.deletePrivateKey(EC_TAG);
    console.log('EC delete success', success);
    return success;
  } catch (e) {
    console.log('keychainECDemo failed:', e);
    return false;
  }
};

export default keychainECDemo;
