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
  | 'SHA256withRSA'
  | 'SHA512withRSA'
  | 'SHA1withRSA'
  | 'SHA256withECDSA'
  | 'SHA512withECDSA'
  | 'SHA1withECDSA';
export interface KeychainItem {
  class: string;
  type: string;
  size: number;
  public: string;
  publicEd25519?: string;
  extractable: boolean;
  tag: string;
  label: string;
  syncronizable: boolean;
  accessControl: string;
}
export const RSA = {
  generate: (): Promise<KeyPair> => RNRSA.generateKeys(2048),
  generateKeys: (keySize: number): Promise<KeyPair> =>
    RNRSA.generateKeys(keySize),
  encrypt: async (data: string, key: string): Promise<string> => {
    return await RNRSA.encrypt64(btoa(data), key);
  },
  decrypt: async (data: string, key: string): Promise<string> => {
    return atob(await RNRSA.decrypt64(data, key));
  },
  encrypt64: (data: string, key: string): Promise<string> =>
    RNRSA.encrypt64(data, key),
  decrypt64: (data: string, key: string): Promise<string> =>
    RNRSA.decrypt64(data, key),
  sign: async (data: string, key: string): Promise<string> => {
    return await RNRSA.sign64WithAlgorithm(btoa(data), key, 'SHA512withRSA');
  },
  signWithAlgorithm: async (
    data: string,
    key: string,
    signature?: TypeCrypto
  ): Promise<string> => {
    return await RNRSA.sign64WithAlgorithm(
      btoa(data),
      key,
      signature ?? 'SHA512withRSA'
    );
  },
  sign64: (data: string, key: string): Promise<string> =>
    RNRSA.sign64WithAlgorithm(data, key),
  sign64WithAlgorithm: (
    data: string,
    key: string,
    signature?: TypeCrypto
  ): Promise<string> =>
    RNRSA.sign64WithAlgorithm(data, key, signature ?? 'SHA512withRSA'),
  verify: async (
    signature: string,
    data: string,
    key: string
  ): Promise<boolean> =>
    RNRSA.verify64WithAlgorithm(signature, btoa(data), key, 'SHA512withRSA'),
  verifyWithAlgorithm: async (
    signature: string,
    data: string,
    key: string,
    algorithm?: TypeCrypto
  ): Promise<boolean> =>
    RNRSA.verify64WithAlgorithm(
      signature,
      btoa(data),
      key,
      algorithm ?? 'SHA512withRSA'
    ),
  verify64: (signature: string, data: string, key: string): Promise<boolean> =>
    RNRSA.verify64WithAlgorithm(signature, data, key, 'SHA512withRSA'),
  verify64WithAlgorithm: (
    signature: string,
    data: string,
    key: string,
    algorithm?: TypeCrypto
  ): Promise<boolean> =>
    RNRSA.verify64WithAlgorithm(
      signature,
      data,
      key,
      algorithm ?? 'SHA512withRSA'
    ),
  SHA256withRSA: RNRSA.SHA256withRSA,
  SHA512withRSA: RNRSA.SHA512withRSA,
  SHA1withRSA: RNRSA.SHA1withRSA,
  SHA256withECDSA: RNRSA.SHA256withECDSA,
  SHA512withECDSA: RNRSA.SHA512withECDSA,
  SHA1withECDSA: RNRSA.SHA1withECDSA,
};

export const RSAKeychain = {
  /**
   * Generate RSA key pair with default 2048-bit key size
   * @param keyTag - Key tag identifier
   * @param synchronizable - Whether key should be synchronizable across devices
   * @param label - Optional label for the key
   * @returns Promise<PublicKey> - Generated public key
   */
  generate: (
    keyTag: string,
    synchronizable?: boolean,
    label?: string
  ): Promise<PublicKey> =>
    RNRSAKeychain.generateKeys(
      keyTag,
      2048,
      synchronizable ?? false,
      label ?? null
    ),
  /**
   * Generate RSA key pair with specified key size
   * @param keyTag - Key tag identifier
   * @param keySize - Key size in bits
   * @param synchronizable - Whether key should be synchronizable across devices
   * @param label - Optional label for the key
   * @returns Promise<PublicKey> - Generated public key
   */
  generateKeys: (
    keyTag: string,
    keySize: number,
    synchronizable?: boolean,
    label?: string
  ): Promise<PublicKey> =>
    RNRSAKeychain.generateKeys(
      keyTag,
      keySize,
      synchronizable ?? false,
      label ?? null
    ),
  /**
   * Generate EC (P-256) key pair
   * @param keyTag - Key tag identifier
   * @param synchronizable - Whether key should be synchronizable across devices
   * @param label - Optional label for the key
   * @returns Promise<PublicKey> - Generated public key
   */
  generateEC: (
    keyTag: string,
    synchronizable?: boolean,
    label?: string
  ): Promise<PublicKey> =>
    RNRSAKeychain.generateEC(keyTag, synchronizable ?? false, label ?? null),
  /**
   * Generate Ed25519 key pair
   * @param keyTag - Key tag identifier
   * @param synchronizable - Whether key should be synchronizable across devices
   * @param label - Optional label for the key
   * @returns Promise<PublicKey> - Generated public key
   */
  generateEd: (
    keyTag: string,
    synchronizable?: boolean,
    label?: string
  ): Promise<PublicKey> =>
    RNRSAKeychain.generateEd(keyTag, synchronizable ?? false, label ?? null),
  /**
   * Generate Certificate Signing Request (CSR)
   * @param keyTag - Key tag identifier
   * @param CN - Common Name for the certificate
   * @param signature - Signature algorithm
   * @returns Promise<CSRKey> - Generated CSR
   */
  generateCSR: (
    keyTag: string,
    CN: string,
    signature?: TypeCrypto
  ): Promise<CSRKey> =>
    RNRSAKeychain.generateCSR(keyTag, CN, signature ?? 'SHA512withRSA'),
  /**
   * Generate CSR with EC key
   * @param cn - Common Name for the certificate
   * @param keyTag - Key tag identifier
   * @param keySize - Key size in bits
   * @returns Promise<PublicKey & CSRKey> - Generated public key and CSR
   */
  generateCSRWithEC: (
    cn: string,
    keyTag: string,
    keySize: number
  ): Promise<PublicKey & CSRKey> =>
    RNRSAKeychain.generateCSRWithEC(cn, keyTag, keySize),
  /**
   * Delete private key from keychain
   * @param keyTag - Key tag identifier
   * @returns Promise<boolean> - True if key was deleted successfully
   */
  deletePrivateKey: (keyTag: string): Promise<boolean> =>
    RNRSAKeychain.deletePrivateKey(keyTag),
  /**
   * Update private key label
   * @param keyTag - Key tag identifier
   * @param label - New label for the key
   * @returns Promise<boolean> - True if key was updated successfully
   */
  updatePrivateKey: (keyTag: string, label: string): Promise<boolean> =>
    RNRSAKeychain.updatePrivateKey(keyTag, label),
  /**
   * Encrypt data (non-64 version - handles raw strings/Uint8Arrays)
   * @param data - Raw string OR Uint8Array to encrypt (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @returns Promise<Uint8Array> - encrypted data
   */
  encrypt: async (
    data: string | Uint8Array,
    keyTag: string
  ): Promise<Uint8Array> => {
    return _fromBase64(await RNRSAKeychain.encrypt64(_toBase64(data), keyTag));
  },
  /**
   * Decrypt data (non-64 version - returns raw string)
   * @param data - Raw string OR Uint8Array (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @returns Promise<string> - Decrypted raw string
   */
  decrypt: async (
    data: string | Uint8Array,
    keyTag: string
  ): Promise<string> => {
    return atob(await RNRSAKeychain.decrypt64(_toBase64(data), keyTag));
  },
  /**
   * Encrypt data (64 version - handles base64 data)
   * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
   * @param keyTag - Key tag identifier
   * @returns Promise<string> - Base64-encoded encrypted data
   */
  encrypt64: (data: string | Uint8Array, keyTag: string): Promise<string> =>
    RNRSAKeychain.encrypt64(_fixupMaybeUint8Array(data), keyTag),
  /**
   * Decrypt data (64 version - handles base64 data)
   * @param data - Base64-encoded encrypted data string OR Uint8Array (passed to native code as-is)
   * @param keyTag - Key tag identifier
   * @returns Promise<string> - Base64-encoded decrypted data
   */
  decrypt64: (data: string | Uint8Array, keyTag: string): Promise<string> =>
    RNRSAKeychain.decrypt64(_fixupMaybeUint8Array(data), keyTag),
  /**
   * Sign data (non-64 version - handles raw strings/Uint8Arrays)
   * @param data - Raw string OR Uint8Array to sign (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @returns Promise<Uint8Array> - signature
   */
  sign: async (
    data: string | Uint8Array,
    keyTag: string
  ): Promise<Uint8Array> => {
    return _fromBase64(
      await RNRSAKeychain.sign64WithAlgorithm(
        _toBase64(data),
        keyTag,
        'SHA512withRSA'
      )
    );
  },
  /**
   * Sign data with algorithm (non-64 version - handles raw strings/Uint8Arrays)
   * @param data - Raw string OR Uint8Array to sign (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @param algorithm - Signature algorithm (default: SHA512withRSA)
   * @returns Promise<Uint8Array> - signature
   */
  signWithAlgorithm: async (
    data: string | Uint8Array,
    keyTag: string,
    algorithm?: TypeCrypto
  ): Promise<Uint8Array> => {
    return _fromBase64(
      await RNRSAKeychain.sign64WithAlgorithm(
        _toBase64(data),
        keyTag,
        algorithm ?? 'SHA512withRSA'
      )
    );
  },
  /**
   * Sign data (64 version - handles base64 data)
   * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
   * @param keyTag - Key tag identifier
   * @returns Promise<string> - Base64-encoded signature
   */
  sign64: (data: string | Uint8Array, keyTag: string): Promise<string> =>
    RNRSAKeychain.sign64WithAlgorithm(
      _fixupMaybeUint8Array(data),
      keyTag,
      'SHA512withRSA'
    ),
  /**
   * Sign data with algorithm (64 version - handles base64 data)
   * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
   * @param keyTag - Key tag identifier
   * @param algorithm - Signature algorithm (default: SHA512withRSA)
   * @returns Promise<string> - Base64-encoded signature
   */
  sign64WithAlgorithm: (
    data: string | Uint8Array,
    keyTag: string,
    algorithm?: TypeCrypto
  ): Promise<string> =>
    RNRSAKeychain.sign64WithAlgorithm(
      _fixupMaybeUint8Array(data),
      keyTag,
      algorithm ?? 'SHA512withRSA'
    ),
  /**
   * Sign a message with Ed25519 private key from keychain
   * @param message - Message to sign: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @returns Promise<Uint8Array> - 64-byte Ed25519 signature
   */
  signEd: async (
    message: string | Uint8Array,
    keyTag: string
  ): Promise<Uint8Array> => {
    const signature = await RNRSAKeychain.signEd(_toBase64(message), keyTag);
    return _fromBase64(signature);
  },
  /**
   * Verify Ed25519 signature
   * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param message - Original message: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param publicKey - Ed25519 public key: raw string OR Uint8Array (will be base64 encoded automatically)
   * @returns Promise<boolean> - True if signature is valid
   */
  verifyEd: async (
    signature: string | Uint8Array,
    message: string | Uint8Array,
    publicKey: string | Uint8Array
  ): Promise<boolean> => {
    return await RNRSAKeychain.verifyEd(
      _toBase64(signature),
      _toBase64(message),
      _toBase64(publicKey)
    );
  },
  /**
   * Verify signature (non-64 version - handles raw strings/Uint8Arrays)
   * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param data - Original data: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @returns Promise<boolean> - True if signature is valid
   */
  verify: async (
    signature: string | Uint8Array,
    data: string | Uint8Array,
    keyTag: string
  ): Promise<boolean> =>
    RNRSAKeychain.verify64WithAlgorithm(
      _toBase64(signature),
      _toBase64(data),
      keyTag,
      'SHA512withRSA'
    ),
  /**
   * Verify signature with algorithm (non-64 version - handles raw strings/Uint8Arrays)
   * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param data - Original data: raw string OR Uint8Array (will be base64 encoded automatically)
   * @param keyTag - Key tag identifier
   * @param algorithm - Signature algorithm (default: SHA512withRSA)
   * @returns Promise<boolean> - True if signature is valid
   */
  verifyWithAlgorithm: async (
    signature: string | Uint8Array,
    data: string | Uint8Array,
    keyTag: string,
    algorithm?: TypeCrypto
  ): Promise<boolean> =>
    RNRSAKeychain.verify64WithAlgorithm(
      _toBase64(signature),
      _toBase64(data),
      keyTag,
      algorithm ?? 'SHA512withRSA'
    ),
  /**
   * Verify signature (64 version - handles base64 data)
   * @param signature - Base64-encoded signature string OR Uint8Array (passed to native code as-is)
   * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
   * @param keyTag - Key tag identifier
   * @returns Promise<boolean> - True if signature is valid
   */
  verify64: (
    signature: string | Uint8Array,
    data: string | Uint8Array,
    keyTag: string
  ): Promise<boolean> =>
    RNRSAKeychain.verify64WithAlgorithm(
      _fixupMaybeUint8Array(signature),
      _fixupMaybeUint8Array(data),
      keyTag,
      'SHA512withRSA'
    ),
  /**
   * Verify signature with algorithm (64 version - handles base64 data)
   * @param signature - Base64-encoded signature string OR Uint8Array (passed to native code as-is)
   * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
   * @param keyTag - Key tag identifier
   * @param algorithm - Signature algorithm (default: SHA512withRSA)
   * @returns Promise<boolean> - True if signature is valid
   */
  verify64WithAlgorithm: (
    signature: string | Uint8Array,
    data: string | Uint8Array,
    keyTag: string,
    algorithm?: TypeCrypto
  ): Promise<boolean> =>
    RNRSAKeychain.verify64WithAlgorithm(
      _fixupMaybeUint8Array(signature),
      _fixupMaybeUint8Array(data),
      keyTag,
      algorithm ?? 'SHA512withRSA'
    ),
  /**
   * Get public key from keychain
   * @param keyTag - Key tag identifier
   * @returns Promise<PublicKey> - Public key
   */
  getPublicKey: (keyTag: string): Promise<PublicKey> =>
    RNRSAKeychain.getPublicKey(keyTag),
  /**
   * Get Ed25519 public key from keychain
   * @param keyTag - Key tag identifier
   * @returns Promise<PublicKey> - Ed25519 public key
   */
  getPublicKeyEd: (keyTag: string): Promise<PublicKey> =>
    RNRSAKeychain.getPublicKeyEd(keyTag),
  /**
   * Get public key in DER format from keychain
   * @param keyTag - Key tag identifier
   * @returns Promise<PublicKey> - Public key in DER format
   */
  getPublicKeyDER: (keyTag: string): Promise<PublicKey> =>
    RNRSAKeychain.getPublicKeyDER(keyTag),
  /**
   * Get RSA public key from keychain
   * @param keyTag - Key tag identifier
   * @returns Promise<PublicKey> - RSA public key
   */
  getPublicKeyRSA: (keyTag: string): Promise<PublicKey> =>
    RNRSAKeychain.getPublicKeyRSA(keyTag),
  /**
   * Get all keys from keychain
   * @returns Promise<KeychainItem[]> - Array of all keychain items
   */
  getAllKeys: (): Promise<KeychainItem[]> => RNRSAKeychain.getAllKeys(),
  /**
   * Delete all keys from keychain
   * @returns Promise<boolean> - True if all keys were deleted successfully
   */
  deleteAllKeys: (): Promise<boolean> => RNRSAKeychain.deleteAllKeys(),
  SHA256withRSA: RNRSAKeychain.SHA256withRSA,
  SHA512withRSA: RNRSAKeychain.SHA512withRSA,
  SHA1withRSA: RNRSAKeychain.SHA1withRSA,
  SHA256withECDSA: RNRSAKeychain.SHA256withECDSA,
  SHA512withECDSA: RNRSAKeychain.SHA512withECDSA,
  SHA1withECDSA: RNRSAKeychain.SHA1withECDSA,
};

function _toBase64(arg: string | Uint8Array): string {
  return typeof arg === 'string'
    ? btoa(arg)
    : btoa(String.fromCharCode(...arg));
}
function _fixupMaybeUint8Array(arg: string | Uint8Array): string {
  return typeof arg === 'string' ? arg : btoa(String.fromCharCode(...arg));
}
function _fromBase64(arg: string): Uint8Array {
  return new Uint8Array(
    atob(arg)
      .split('')
      .map((c) => c.charCodeAt(0))
  );
}

export { RNRSAKeychain, RNRSA };
export default RNRSA;
