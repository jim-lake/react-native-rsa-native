import { RSA } from 'react-native-rsa-native';

let secret = 'secret message';

const signAlgoDemo = async () => {
  try {
    console.log('signAlgoDemo');
    const keys = await RSA.generate();
    const signature = await RSA.signWithAlgorithm(
      secret,
      keys.private,
      RSA.SHA256withRSA,
    );
    console.log('signature', signature);

    // Validate signature format - RSA signatures are raw bytes, not ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // RSA signatures should be exactly the key size in bytes (2048 bits = 256 bytes)
      if (sigData.length === 256) {
        console.log('Signature format valid (256 bytes for 2048-bit key)');
      } else {
        console.log(`Unexpected signature length: ${sigData.length} bytes`);
        return false;
      }
    } catch (parseErr) {
      console.log('Signature parsing failed:', parseErr);
      return false;
    }

    const valid = await RSA.verifyWithAlgorithm(
      signature,
      secret,
      keys.public,
      RSA.SHA256withRSA,
    );
    console.log('verified', valid);
    if (!valid) return false;

    try {
      await RSA.verifyWithAlgorithm(
        signature,
        'wrong message',
        keys.public,
        RSA.SHA256withRSA,
      );
      console.log(
        'NOTE!! Something went wrong, verify should have been failed',
      );
      return false;
    } catch (err) {
      console.log('verify fails correctly: ', err);
      return true;
    }
  } catch (e) {
    console.log('signAlgoDemo failed:', e);
    return false;
  }
};

export default signAlgoDemo;
