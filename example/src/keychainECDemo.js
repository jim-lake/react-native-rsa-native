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
    console.log('keychainECDemo start - EC API Coverage Tests');

    // Test 1: Cross-verification (existing test)
    console.log('\n=== Test 1: EC Cross-Verification ===');
    const EC_TAG = 'ec_tag1';
    await RSAKeychain.deletePrivateKey(EC_TAG);
    const keys = await RSAKeychain.generateEC(EC_TAG, false, 'Test EC Key');

    let did_print = false;
    let iterations = 100;
    for (let i = 0; i < iterations; i++) {
      const message = 'test message' + Math.random();
      const messageBytes = new TextEncoder().encode(message);

      const publicBytes = base64ToUint8Array(keys.public);

      const nativeSignature = await RSAKeychain.sign64WithAlgorithm(
        messageBytes,
        EC_TAG,
        'SHA256withECDSA',
      );
      const nativeSignatureBytes = base64ToUint8Array(nativeSignature);

      let crossVerifyResult = false;
      try {
        crossVerifyResult = p256.verify(
          nativeSignatureBytes,
          messageBytes,
          publicBytes,
          { format: 'der', lowS: false },
        );
      } catch (e) {
        console.log('Cross-verification error:', e);
        crossVerifyResult = false;
      }
      const nativeVerifyResult = await RSAKeychain.verify64WithAlgorithm(
        nativeSignatureBytes,
        messageBytes,
        EC_TAG,
        'SHA256withECDSA',
      );
      const failed = !crossVerifyResult || !nativeVerifyResult;

      if (failed || !did_print) {
        did_print = true;

        if (failed) {
          console.log('fail on iteration:', i);
        }

        console.log('message:', message);
        console.log('messageBytes:', _uint8ArrayToHex(messageBytes));
        console.log('public:', keys.public);
        console.log('publicBytes:', _uint8ArrayToHex(publicBytes));
        console.log('nativeSignature:', nativeSignature);
        console.log(
          'nativeSignatureBytes:',
          _uint8ArrayToHex(nativeSignatureBytes),
        );
        if (crossVerifyResult) {
          console.log('✅ EC Cross-verification SUCCESS!');
        } else {
          console.log('❌ Cross-verification failed');
        }
        console.log('Native verification result:', nativeVerifyResult);
        if (failed) {
          return false;
        }
      }
    }
    console.log('iterations:', iterations, 'success!');

    // Test 2: Non-64 API methods
    console.log('\n=== Test 2: Non-64 API Methods ===');
    const message = 'test message for non-64 APIs';
    
    const signature = await RSAKeychain.signWithAlgorithm(message, EC_TAG, 'SHA256withECDSA');
    console.log('signWithAlgorithm result length:', signature.length);
    
    const verifyResult = await RSAKeychain.verifyWithAlgorithm(signature, message, EC_TAG, 'SHA256withECDSA');
    console.log('verifyWithAlgorithm result:', verifyResult);
    if (!verifyResult) {
      console.log('❌ Non-64 API verification failed');
      return false;
    }
    console.log('✅ Non-64 API methods SUCCESS!');

    // Test 3: Different ECDSA algorithms
    console.log('\n=== Test 3: ECDSA Algorithm Variants ===');
    const algorithms = ['SHA256withECDSA', 'SHA512withECDSA', 'SHA1withECDSA'];
    
    for (const algo of algorithms) {
      console.log(`Testing ${algo}...`);
      const testMessage = new TextEncoder().encode(message);
      const sig = await RSAKeychain.sign64WithAlgorithm(testMessage, EC_TAG, algo);
      const verify = await RSAKeychain.verify64WithAlgorithm(sig, testMessage, EC_TAG, algo);
      if (!verify) {
        console.log(`❌ ${algo} verification failed`);
        return false;
      }
      console.log(`✅ ${algo} SUCCESS!`);
    }

    // Test 4: Public key retrieval methods
    console.log('\n=== Test 4: Public Key Retrieval ===');
    
    const pubKey = await RSAKeychain.getPublicKey(EC_TAG);
    console.log('getPublicKey result length:', pubKey.public.length);
    
    const pubKeyDER = await RSAKeychain.getPublicKeyDER(EC_TAG);
    console.log('getPublicKeyDER result length:', pubKeyDER.public.length);
    
    if (!pubKey.public || !pubKeyDER.public) {
      console.log('❌ Public key retrieval failed');
      return false;
    }
    console.log('✅ Public key retrieval SUCCESS!');

    await RSAKeychain.deletePrivateKey(EC_TAG);
    console.log('\n✅ All EC API tests completed successfully!');
    return true;
  } catch (e) {
    console.log('keychainECDemo failed:', e);
    return false;
  }
};
function _uint8ArrayToHex(a) {
  return Array.from(a)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export default keychainECDemo;
