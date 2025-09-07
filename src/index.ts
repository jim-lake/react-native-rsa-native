import { NativeModules } from 'react-native';

const { RNRSAKeychain, RNRSA } = NativeModules;

export interface PublicKey {
  public: string;
}

export interface CSRKey {
  csr: string;
}

export interface KeyPair extends PublicKey {
  private: string;
}

export type TypeCrypto = 
  'SHA256withRSA' |
  'SHA512withRSA' |
  'SHA1withRSA' |
  'SHA256withECDSA' |
  'SHA512withECDSA' |
  'SHA1withECDSA';

export const RSA = {
  generate: (): Promise<KeyPair> => RNRSA.generateKeys(2048),
  generateKeys: (keySize: number): Promise<KeyPair> => RNRSA.generateKeys(keySize),
  encrypt: async (data: string, key: string): Promise<string> => {
    return await RNRSA.encrypt64(btoa(data), key);
  },
  decrypt: async (data: string, key: string): Promise<string> => {
    return await RNRSA.decrypt64(btoa(data), key);
  },
  encrypt64: (data: string, key: string): Promise<string> => RNRSA.encrypt64(data, key),
  decrypt64: (data: string, key: string): Promise<string> => RNRSA.decrypt64(data, key),
  sign: async (data: string, key: string): Promise<string> => {
    return await RNRSA.sign64WithAlgorithm(btoa(data), key, 'SHA512withRSA');
  },
  signWithAlgorithm: async (data: string, key: string, signature?: TypeCrypto): Promise<string> => {
    return await RNRSA.sign64WithAlgorithm(btoa(data), key, signature || 'SHA512withRSA');
  },
  sign64: (data: string, key: string): Promise<string> => RNRSA.sign64WithAlgorithm(data, key, 'SHA512withRSA'),
  sign64WithAlgorithm: (data: string, key: string, signature?: TypeCrypto): Promise<string> => 
    RNRSA.sign64WithAlgorithm(data, key, signature),
  verify: async (signature: string, data: string, key: string): Promise<boolean> => 
    RNRSA.verify64WithAlgorithm(btoa(signature), btoa(data), key, 'SHA512withRSA'),
  verifyWithAlgorithm: async (signature: string, data: string, key: string, algorithm?: TypeCrypto): Promise<boolean> => 
    RNRSA.verify64WithAlgorithm(btoa(signature), btoa(data), key, algorithm || 'SHA512withRSA'),
  verify64: (signature: string, data: string, key: string): Promise<boolean> => 
    RNRSA.verify64WithAlgorithm(signature, data, key, 'SHA512withRSA'),
  verify64WithAlgorithm: (signature: string, data: string, key: string, algorithm?: TypeCrypto): Promise<boolean> => 
    RNRSA.verify64WithAlgorithm(signature, data, key, algorithm),
  SHA256withRSA: RNRSA.SHA256withRSA,
  SHA512withRSA: RNRSA.SHA512withRSA,
  SHA1withRSA: RNRSA.SHA1withRSA,
  SHA256withECDSA: RNRSA.SHA256withECDSA,
  SHA512withECDSA: RNRSA.SHA512withECDSA,
  SHA1withECDSA: RNRSA.SHA1withECDSA,
};

export const RSAKeychain = {
  generate: (keyTag: string): Promise<PublicKey> => RNRSAKeychain.generateKeys(keyTag, 2048),
  generateKeys: (keyTag: string, keySize: number): Promise<PublicKey> => 
    RNRSAKeychain.generateKeys(keyTag, keySize),
  generateEC: (keyTag: string): Promise<PublicKey> => RNRSAKeychain.generateEC(keyTag),
  generateCSR: (keyTag: string, CN: string, signature?: TypeCrypto): Promise<CSRKey> => 
    RNRSAKeychain.generateCSR(keyTag, CN, signature || 'SHA512withRSA'),
  generateCSRWithEC: (cn: string, keyTag: string, keySize: number): Promise<PublicKey & CSRKey> => 
    RNRSAKeychain.generateCSRWithEC(cn, keyTag, keySize),
  deletePrivateKey: (keyTag: string): Promise<boolean> => RNRSAKeychain.deletePrivateKey(keyTag),
  encrypt: async (data: string, keyTag: string): Promise<string> => {
    return await RNRSAKeychain.encrypt64(btoa(data), keyTag);
  },
  decrypt: async (data: string, keyTag: string): Promise<string> => {
    return await RNRSAKeychain.decrypt64(btoa(data), keyTag);
  },
  encrypt64: (data: string, keyTag: string): Promise<string> => RNRSAKeychain.encrypt64(data, keyTag),
  decrypt64: (data: string, keyTag: string): Promise<string> => RNRSAKeychain.decrypt64(data, keyTag),
  sign: async (data: string, keyTag: string): Promise<string> => {
    return await RNRSAKeychain.sign64WithAlgorithm(btoa(data), keyTag, 'SHA512withRSA');
  },
  signWithAlgorithm: async (data: string, keyTag: string, signature?: TypeCrypto): Promise<string> => {
    return await RNRSAKeychain.sign64WithAlgorithm(btoa(data), keyTag, signature || 'SHA512withRSA');
  },
  sign64: (data: string, keyTag: string): Promise<string> => RNRSAKeychain.sign64WithAlgorithm(data, keyTag, 'SHA512withRSA'),
  sign64WithAlgorithm: (data: string, keyTag: string, signature?: TypeCrypto): Promise<string> => 
    RNRSAKeychain.sign64WithAlgorithm(data, keyTag, signature || 'SHA512withRSA'),
  verify: async (signature: string, data: string, keyTag: string): Promise<boolean> => 
    RNRSAKeychain.verify64WithAlgorithm(btoa(signature), btoa(data), keyTag, 'SHA512withRSA'),
  verifyWithAlgorithm: async (signature: string, data: string, keyTag: string, algorithm?: TypeCrypto): Promise<boolean> => 
    RNRSAKeychain.verify64WithAlgorithm(btoa(signature), btoa(data), keyTag, algorithm || 'SHA512withRSA'),
  verify64: (signature: string, data: string, keyTag: string): Promise<boolean> => 
    RNRSAKeychain.verify64WithAlgorithm(signature, data, keyTag, 'SHA512withRSA'),
  verify64WithAlgorithm: (signature: string, data: string, keyTag: string, algorithm?: TypeCrypto): Promise<boolean> => 
    RNRSAKeychain.verify64WithAlgorithm(signature, data, keyTag, algorithm || 'SHA512withRSA'),
  getPublicKey: (keyTag: string): Promise<PublicKey> => RNRSAKeychain.getPublicKey(keyTag),
  getPublicKeyDER: (keyTag: string): Promise<PublicKey> => RNRSAKeychain.getPublicKeyDER(keyTag),
  getPublicKeyRSA: (keyTag: string): Promise<PublicKey> => RNRSAKeychain.getPublicKeyRSA(keyTag),
  getAllKeys: (): Promise<any[]> => RNRSAKeychain.getAllKeys(),
  deleteAllKeys: (): Promise<boolean> => RNRSAKeychain.deleteAllKeys(),
  SHA256withRSA: RNRSAKeychain.SHA256withRSA,
  SHA512withRSA: RNRSAKeychain.SHA512withRSA,
  SHA1withRSA: RNRSAKeychain.SHA1withRSA,
  SHA256withECDSA: RNRSAKeychain.SHA256withECDSA,
  SHA512withECDSA: RNRSAKeychain.SHA512withECDSA,
  SHA1withECDSA: RNRSAKeychain.SHA1withECDSA,
};

export { RNRSAKeychain, RNRSA };
export default RNRSA;
