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

    const encodedMessage = await RSAKeychain.encrypt(secret, RSA_TAG);
    console.log('encodedMessage:', encodedMessage);
    const message = await RSAKeychain.decrypt(encodedMessage, RSA_TAG);
    console.log('message:', message);
    const signature = await RSAKeychain.sign(secret, RSA_TAG);
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

    const valid = await RSAKeychain.verify(signature, secret, RSA_TAG);
    console.log('verified', valid);
    if (!valid) {
      return false;
    }

    const invalid = await RSAKeychain.verify(
      signature,
      'wrong message',
      RSA_TAG,
    );
    console.log('invalid:', invalid);
    if (invalid) {
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
