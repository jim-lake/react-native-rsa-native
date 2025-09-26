"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RNRSA = exports.RNRSAKeychain = exports.RSAKeychain = exports.RSA = void 0;
const react_native_1 = require("react-native");
const { RNRSAKeychain, RNRSA } = react_native_1.NativeModules;
exports.RNRSAKeychain = RNRSAKeychain;
exports.RNRSA = RNRSA;
exports.RSA = {
    generate: () => RNRSA.generateKeys(2048),
    generateKeys: (keySize) => RNRSA.generateKeys(keySize),
    encrypt: async (data, key) => {
        return await RNRSA.encrypt64(btoa(data), key);
    },
    decrypt: async (data, key) => {
        return atob(await RNRSA.decrypt64(data, key));
    },
    encrypt64: (data, key) => RNRSA.encrypt64(data, key),
    decrypt64: (data, key) => RNRSA.decrypt64(data, key),
    sign: async (data, key) => {
        return await RNRSA.sign64WithAlgorithm(btoa(data), key, 'SHA512withRSA');
    },
    signWithAlgorithm: async (data, key, signature) => {
        return await RNRSA.sign64WithAlgorithm(btoa(data), key, signature !== null && signature !== void 0 ? signature : 'SHA512withRSA');
    },
    sign64: (data, key) => RNRSA.sign64WithAlgorithm(data, key),
    sign64WithAlgorithm: (data, key, signature) => RNRSA.sign64WithAlgorithm(data, key, signature !== null && signature !== void 0 ? signature : 'SHA512withRSA'),
    verify: async (signature, data, key) => RNRSA.verify64WithAlgorithm(signature, btoa(data), key, 'SHA512withRSA'),
    verifyWithAlgorithm: async (signature, data, key, algorithm) => RNRSA.verify64WithAlgorithm(signature, btoa(data), key, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    verify64: (signature, data, key) => RNRSA.verify64WithAlgorithm(signature, data, key, 'SHA512withRSA'),
    verify64WithAlgorithm: (signature, data, key, algorithm) => RNRSA.verify64WithAlgorithm(signature, data, key, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    SHA256withRSA: RNRSA.SHA256withRSA,
    SHA512withRSA: RNRSA.SHA512withRSA,
    SHA1withRSA: RNRSA.SHA1withRSA,
    SHA256withECDSA: RNRSA.SHA256withECDSA,
    SHA512withECDSA: RNRSA.SHA512withECDSA,
    SHA1withECDSA: RNRSA.SHA1withECDSA,
};
exports.RSAKeychain = {
    /**
     * Generate RSA key pair with default 2048-bit key size
     * @param keyTag - Key tag identifier
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generate: (keyTag, synchronizable, label) => RNRSAKeychain.generateKeys(keyTag, 2048, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    /**
     * Generate RSA key pair with specified key size
     * @param keyTag - Key tag identifier
     * @param keySize - Key size in bits
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generateKeys: (keyTag, keySize, synchronizable, label) => RNRSAKeychain.generateKeys(keyTag, keySize, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    /**
     * Generate EC (P-256) key pair
     * @param keyTag - Key tag identifier
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generateEC: (keyTag, synchronizable, label) => RNRSAKeychain.generateEC(keyTag, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    /**
     * Generate Ed25519 key pair
     * @param keyTag - Key tag identifier
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generateEd: (keyTag, synchronizable, label) => RNRSAKeychain.generateEd(keyTag, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    /**
     * Generate Certificate Signing Request (CSR)
     * @param keyTag - Key tag identifier
     * @param CN - Common Name for the certificate
     * @param signature - Signature algorithm
     * @returns Promise<CSRKey> - Generated CSR
     */
    generateCSR: (keyTag, CN, signature) => RNRSAKeychain.generateCSR(keyTag, CN, signature !== null && signature !== void 0 ? signature : 'SHA512withRSA'),
    /**
     * Generate CSR with EC key
     * @param cn - Common Name for the certificate
     * @param keyTag - Key tag identifier
     * @param keySize - Key size in bits
     * @returns Promise<PublicKey & CSRKey> - Generated public key and CSR
     */
    generateCSRWithEC: (cn, keyTag, keySize) => RNRSAKeychain.generateCSRWithEC(cn, keyTag, keySize),
    /**
     * Delete private key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<boolean> - True if key was deleted successfully
     */
    deletePrivateKey: (keyTag) => RNRSAKeychain.deletePrivateKey(keyTag),
    /**
     * Update private key label
     * @param keyTag - Key tag identifier
     * @param label - New label for the key
     * @returns Promise<boolean> - True if key was updated successfully
     */
    updatePrivateKey: (keyTag, label) => RNRSAKeychain.updatePrivateKey(keyTag, label),
    /**
     * Encrypt data (non-64 version - handles raw strings/Uint8Arrays)
     * @param data - Raw string OR Uint8Array to encrypt (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<Uint8Array> - encrypted data
     */
    encrypt: async (data, keyTag) => {
        return _fromBase64(await RNRSAKeychain.encrypt64(_toBase64(data), keyTag));
    },
    /**
     * Decrypt data (non-64 version - returns raw string)
     * @param data - Raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Decrypted raw string
     */
    decrypt: async (data, keyTag) => {
        return atob(await RNRSAKeychain.decrypt64(_toBase64(data), keyTag));
    },
    /**
     * Encrypt data (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded encrypted data
     */
    encrypt64: (data, keyTag) => RNRSAKeychain.encrypt64(_fixupMaybeUint8Array(data), keyTag),
    /**
     * Decrypt data (64 version - handles base64 data)
     * @param data - Base64-encoded encrypted data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded decrypted data
     */
    decrypt64: (data, keyTag) => RNRSAKeychain.decrypt64(_fixupMaybeUint8Array(data), keyTag),
    /**
     * Sign data (non-64 version - handles raw strings/Uint8Arrays)
     * @param data - Raw string OR Uint8Array to sign (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<Uint8Array> - signature
     */
    sign: async (data, keyTag) => {
        return _fromBase64(await RNRSAKeychain.sign64WithAlgorithm(_toBase64(data), keyTag, 'SHA512withRSA'));
    },
    /**
     * Sign data with algorithm (non-64 version - handles raw strings/Uint8Arrays)
     * @param data - Raw string OR Uint8Array to sign (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<Uint8Array> - signature
     */
    signWithAlgorithm: async (data, keyTag, algorithm) => {
        return _fromBase64(await RNRSAKeychain.sign64WithAlgorithm(_toBase64(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'));
    },
    /**
     * Sign data (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded signature
     */
    sign64: (data, keyTag) => RNRSAKeychain.sign64WithAlgorithm(_fixupMaybeUint8Array(data), keyTag, 'SHA512withRSA'),
    /**
     * Sign data with algorithm (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<string> - Base64-encoded signature
     */
    sign64WithAlgorithm: (data, keyTag, algorithm) => RNRSAKeychain.sign64WithAlgorithm(_fixupMaybeUint8Array(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    /**
     * Sign a message with Ed25519 private key from keychain
     * @param message - Message to sign: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<Uint8Array> - 64-byte Ed25519 signature
     */
    signEd: async (message, keyTag) => {
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
    verifyEd: async (signature, message, publicKey) => {
        return await RNRSAKeychain.verifyEd(_toBase64(signature), _toBase64(message), _toBase64(publicKey));
    },
    /**
     * Verify signature (non-64 version - handles raw strings/Uint8Arrays)
     * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param data - Original data: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<boolean> - True if signature is valid
     */
    verify: async (signature, data, keyTag) => RNRSAKeychain.verify64WithAlgorithm(_toBase64(signature), _toBase64(data), keyTag, 'SHA512withRSA'),
    /**
     * Verify signature with algorithm (non-64 version - handles raw strings/Uint8Arrays)
     * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param data - Original data: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<boolean> - True if signature is valid
     */
    verifyWithAlgorithm: async (signature, data, keyTag, algorithm) => RNRSAKeychain.verify64WithAlgorithm(_toBase64(signature), _toBase64(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    /**
     * Verify signature (64 version - handles base64 data)
     * @param signature - Base64-encoded signature string OR Uint8Array (passed to native code as-is)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<boolean> - True if signature is valid
     */
    verify64: (signature, data, keyTag) => RNRSAKeychain.verify64WithAlgorithm(_fixupMaybeUint8Array(signature), _fixupMaybeUint8Array(data), keyTag, 'SHA512withRSA'),
    /**
     * Verify signature with algorithm (64 version - handles base64 data)
     * @param signature - Base64-encoded signature string OR Uint8Array (passed to native code as-is)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<boolean> - True if signature is valid
     */
    verify64WithAlgorithm: (signature, data, keyTag, algorithm) => RNRSAKeychain.verify64WithAlgorithm(_fixupMaybeUint8Array(signature), _fixupMaybeUint8Array(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    /**
     * Get public key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - Public key
     */
    getPublicKey: (keyTag) => RNRSAKeychain.getPublicKey(keyTag),
    /**
     * Get Ed25519 public key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - Ed25519 public key
     */
    getPublicKeyEd: (keyTag) => RNRSAKeychain.getPublicKeyEd(keyTag),
    /**
     * Get public key in DER format from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - Public key in DER format
     */
    getPublicKeyDER: (keyTag) => RNRSAKeychain.getPublicKeyDER(keyTag),
    /**
     * Get RSA public key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - RSA public key
     */
    getPublicKeyRSA: (keyTag) => RNRSAKeychain.getPublicKeyRSA(keyTag),
    /**
     * Get all keys from keychain
     * @returns Promise<KeychainItem[]> - Array of all keychain items
     */
    getAllKeys: () => RNRSAKeychain.getAllKeys(),
    /**
     * Delete all keys from keychain
     * @returns Promise<boolean> - True if all keys were deleted successfully
     */
    deleteAllKeys: () => RNRSAKeychain.deleteAllKeys(),
    SHA256withRSA: RNRSAKeychain.SHA256withRSA,
    SHA512withRSA: RNRSAKeychain.SHA512withRSA,
    SHA1withRSA: RNRSAKeychain.SHA1withRSA,
    SHA256withECDSA: RNRSAKeychain.SHA256withECDSA,
    SHA512withECDSA: RNRSAKeychain.SHA512withECDSA,
    SHA1withECDSA: RNRSAKeychain.SHA1withECDSA,
};
function _toBase64(arg) {
    return typeof arg === 'string'
        ? btoa(arg)
        : btoa(String.fromCharCode(...arg));
}
function _fixupMaybeUint8Array(arg) {
    return typeof arg === 'string' ? arg : btoa(String.fromCharCode(...arg));
}
function _fromBase64(arg) {
    return new Uint8Array(atob(arg)
        .split('')
        .map((c) => c.charCodeAt(0)));
}
exports.default = RNRSA;
