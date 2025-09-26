import { RSAKeychain } from 'react-native-rsa-native';
import { p256 } from '@noble/curves/nist';

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function parseDERSignature(derBytes) {
  let pos = 2; // Skip SEQUENCE tag and length

  // Parse r
  pos++; // Skip INTEGER tag
  const rLen = derBytes[pos++];
  let r = derBytes.slice(pos, pos + rLen);
  pos += rLen;

  // Parse s
  pos++; // Skip INTEGER tag
  const sLen = derBytes[pos++];
  let s = derBytes.slice(pos, pos + sLen);

  return { r, s };
}

const keychainECDemo = async () => {
  try {
    console.log('keychainECDemo start - EC Cross-Verification');

    const EC_TAG = 'ec_tag1';
    await RSAKeychain.deletePrivateKey(EC_TAG);
    const keys = await RSAKeychain.generateEC(EC_TAG, false, 'Test EC Key');

    const testMessage = 'test message';
    const messageBytes = new TextEncoder().encode(testMessage);

    // Get native signature
    const nativeSignature = await RSAKeychain.sign64WithAlgorithm(
      messageBytes,
      EC_TAG,
      'SHA256withECDSA',
    );

    const nativeSignatureBytes = base64ToUint8Array(nativeSignature);
    const { r, s } = parseDERSignature(nativeSignatureBytes);

    // Remove leading zeros and create r||s BE padded signature (EXACT working implementation)
    const rClean = r[0] === 0 ? r.slice(1) : r;
    const sClean = s[0] === 0 ? s.slice(1) : s;
    const signature = new Uint8Array(64);
    signature.set(rClean, 32 - rClean.length);
    signature.set(sClean, 64 - sClean.length);

    // Create compressed public key (EXACT working implementation)
    const publicKeyBytes = base64ToUint8Array(keys.public);
    const publicKeyForNoble = publicKeyBytes.slice(1); // Remove 0x04 prefix
    const x = publicKeyForNoble.slice(0, 32);
    const y = publicKeyForNoble.slice(32, 64);
    const compressedKey = new Uint8Array(33);
    compressedKey[0] = y[31] % 2 === 0 ? 0x02 : 0x03;
    compressedKey.set(x, 1);

    // Cross-verify: noble crypto verifies native signature (EXACT working combination)
    let crossVerifyResult = false;
    try {
      crossVerifyResult = p256.verify(signature, messageBytes, compressedKey);
      console.log('Cross-verification result:', crossVerifyResult);
      if (crossVerifyResult) {
        console.log('✅ EC Cross-verification SUCCESS!');
      } else {
        console.log('❌ Cross-verification failed');
      }
    } catch (e) {
      console.log('Cross-verification error:', e.message);
      crossVerifyResult = false;
    }

    // Native verify (for comparison)
    const nativeVerifyResult = await RSAKeychain.verify64WithAlgorithm(
      nativeSignatureBytes,
      messageBytes,
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('Native verification result:', nativeVerifyResult);

    await RSAKeychain.deletePrivateKey(EC_TAG);

    return crossVerifyResult && nativeVerifyResult;
  } catch (e) {
    console.log('keychainECDemo failed:', e);
    return false;
  }
};

export default keychainECDemo;
