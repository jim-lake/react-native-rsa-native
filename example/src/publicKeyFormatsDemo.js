import { RSAKeychain } from 'react-native-rsa-native';
import { fromBER } from 'asn1js';
import { PublicKeyInfo } from 'pkijs';

const publicKeyFormatsDemo = async () => {
  console.log('publicKeyFormatsDemo start');

  const keyTag = 'format_test_key';

  try {
    // Generate keychain key and get all formats
    await RSAKeychain.generateKeys(keyTag, 2048);
    const publicKeyDefault = await RSAKeychain.getPublicKey(keyTag);
    const publicKeyDER = await RSAKeychain.getPublicKeyDER(keyTag);
    const publicKeyRSA = await RSAKeychain.getPublicKeyRSA(keyTag);
    const allKeys = await RSAKeychain.getAllKeys();
    const matchingKey = allKeys.find(key => key.tag === keyTag);
    if (!matchingKey) {
      console.log("All keys didn't find key");
      return false;
    }

    console.log('Default public key:', publicKeyDefault.public);
    console.log('DER public key:', publicKeyDER.public);
    console.log('RSA public key:', publicKeyRSA.public);
    console.log('getAllKeys public key:', matchingKey.public);

    // Extract n and e from each format
    const extractRSAParams = (keyStr, format = 'SPKI') => {
      try {
        let keyData;

        if (format === 'RAW') {
          // RAW must be pure base64 with no PEM headers
          if (/-----/.test(keyStr)) {
            console.error('RAW format cannot have PEM headers');
            throw new Error('RAW key must be pure base64 PKCS#1 bytes');
          }
          keyData = Uint8Array.from(atob(keyStr.replace(/\s/g, '')), c =>
            c.charCodeAt(0),
          );
        } else {
          // SPKI or PKCS1 expects PEM
          if (!/-----/.test(keyStr)) {
            console.error(`${format} format requires PEM headers`);
            throw new Error(`${format} key must include PEM headers`);
          }
          const pemContent = keyStr
            .replace(/-----BEGIN [^-]+-----/, '')
            .replace(/-----END [^-]+-----/, '')
            .replace(/\s/g, '');
          keyData = Uint8Array.from(atob(pemContent), c => c.charCodeAt(0));
        }

        const asn1 = fromBER(keyData.buffer);
        if (asn1.offset === -1) {
          console.error('ASN.1 parsing failed');
          throw new Error('Invalid key format');
        }

        let nHex, eHex;

        if (format === 'SPKI') {
          try {
            const publicKeyInfo = new PublicKeyInfo({ schema: asn1.result });
            const keyAsn1 = fromBER(
              publicKeyInfo.subjectPublicKey.valueBlock.valueHex,
            );
            const n = keyAsn1.result.valueBlock.value[0].valueBlock.valueHex;
            const e = keyAsn1.result.valueBlock.value[1].valueBlock.valueHex;
            nHex = Array.from(new Uint8Array(n))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
            eHex = Array.from(new Uint8Array(e))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
          } catch {
            console.error('Key does not match SPKI format');
            throw new Error('Key does not match SPKI format');
          }
        } else if (format === 'PKCS1' || format === 'RAW') {
          try {
            const n = asn1.result.valueBlock.value[0].valueBlock.valueHex;
            const e = asn1.result.valueBlock.value[1].valueBlock.valueHex;
            nHex = Array.from(new Uint8Array(n))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
            eHex = Array.from(new Uint8Array(e))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
          } catch {
            console.error(`Key does not match ${format} PKCS#1 format`);
            throw new Error(`Key does not match ${format} PKCS#1 format`);
          }
        } else {
          throw new Error(`Unsupported format: ${format}`);
        }

        return { n: nHex, e: eHex };
      } catch (e) {
        console.error('Extraction error:', e);
        return null;
      }
    };

    const defaultParams = extractRSAParams(publicKeyDefault.public, 'PKCS1');
    const derParams = extractRSAParams(publicKeyDER.public, 'SPKI');
    const rsaParams = extractRSAParams(publicKeyRSA.public, 'PKCS1');
    const allKeysParams = extractRSAParams(matchingKey.public, 'RAW');

    console.log('Default key n:', defaultParams.n.substring(0, 50) + '...');
    console.log('Default key e:', defaultParams.e);
    console.log('DER key n:', derParams.n.substring(0, 50) + '...');
    console.log('DER key e:', derParams.e);
    console.log('RSA key n:', rsaParams.n.substring(0, 50) + '...');
    console.log('RSA key e:', rsaParams.e);
    console.log('getAllKeys key n:', allKeysParams.n.substring(0, 50) + '...');
    console.log('getAllKeys key e:', allKeysParams.e);

    // Compare n and e
    const sameN =
      defaultParams.n === derParams.n &&
      derParams.n === rsaParams.n &&
      rsaParams.n === allKeysParams.n;
    const sameE =
      defaultParams.e === derParams.e &&
      derParams.e === rsaParams.e &&
      rsaParams.e === allKeysParams.e;

    console.log('Same modulus (n):', sameN);
    console.log('Same exponent (e):', sameE);
    console.log('All keys identical:', sameN && sameE);

    // Clean up
    await RSAKeychain.deletePrivateKey(keyTag);

    return sameN && sameE;
  } catch (e) {
    console.log('publicKeyFormatsDemo error:', e);
    return false;
  }
};

export default publicKeyFormatsDemo;
