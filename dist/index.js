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
    generate: (keyTag, synchronizable, label) => RNRSAKeychain.generateKeys(keyTag, 2048, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    generateKeys: (keyTag, keySize, synchronizable, label) => RNRSAKeychain.generateKeys(keyTag, keySize, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    generateEC: (keyTag, synchronizable, label) => RNRSAKeychain.generateEC(keyTag, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    generateEd: (keyTag, synchronizable, label) => RNRSAKeychain.generateEd(keyTag, synchronizable !== null && synchronizable !== void 0 ? synchronizable : false, label !== null && label !== void 0 ? label : null),
    generateCSR: (keyTag, CN, signature) => RNRSAKeychain.generateCSR(keyTag, CN, signature !== null && signature !== void 0 ? signature : 'SHA512withRSA'),
    generateCSRWithEC: (cn, keyTag, keySize) => RNRSAKeychain.generateCSRWithEC(cn, keyTag, keySize),
    deletePrivateKey: (keyTag) => RNRSAKeychain.deletePrivateKey(keyTag),
    updatePrivateKey: (keyTag, label) => RNRSAKeychain.updatePrivateKey(keyTag, label),
    encrypt: async (data, keyTag) => {
        return await RNRSAKeychain.encrypt64(_toBase64(data), keyTag);
    },
    decrypt: async (data, keyTag) => {
        return atob(await RNRSAKeychain.decrypt64(_fixupMaybeUint8Array(data), keyTag));
    },
    encrypt64: (data, keyTag) => RNRSAKeychain.encrypt64(_fixupMaybeUint8Array(data), keyTag),
    decrypt64: (data, keyTag) => RNRSAKeychain.decrypt64(_fixupMaybeUint8Array(data), keyTag),
    sign: async (data, keyTag) => {
        return await RNRSAKeychain.sign64WithAlgorithm(_toBase64(data), keyTag, 'SHA512withRSA');
    },
    signWithAlgorithm: async (data, keyTag, algorithm) => {
        return await RNRSAKeychain.sign64WithAlgorithm(_toBase64(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA');
    },
    sign64: (data, keyTag) => RNRSAKeychain.sign64WithAlgorithm(_fixupMaybeUint8Array(data), keyTag),
    /**
     * Sign data with algorithm (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (will be base64 encoded automatically)
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
     * @param signature - Signature: string OR Uint8Array (will be base64 encoded automatically)
     * @param message - Original message: string OR Uint8Array (will be base64 encoded automatically)
     * @param publicKey - Ed25519 public key: base64 string OR Uint8Array (will be base64 encoded automatically)
     * @returns Promise<boolean> - True if signature is valid
     */
    verifyEd: async (signature, message, publicKey) => {
        return await RNRSAKeychain.verifyEd(_toBase64(signature), _toBase64(message), _fixupMaybeUint8Array(publicKey));
    },
    verify: async (signature, data, keyTag) => RNRSAKeychain.verify64WithAlgorithm(_toBase64(signature), _toBase64(data), keyTag, 'SHA512withRSA'),
    verifyWithAlgorithm: async (signature, data, keyTag, algorithm) => RNRSAKeychain.verify64WithAlgorithm(_toBase64(signature), _toBase64(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    verify64: (signature, data, keyTag) => RNRSAKeychain.verify64WithAlgorithm(_fixupMaybeUint8Array(signature), _fixupMaybeUint8Array(data), keyTag),
    /**
     * Verify signature with algorithm (64 version - handles base64 data)
     * @param signature - Signature: base64 string OR Uint8Array (will be base64 encoded automatically)
     * @param data - Base64-encoded data string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<boolean> - True if signature is valid
     */
    verify64WithAlgorithm: (signature, data, keyTag, algorithm) => RNRSAKeychain.verify64WithAlgorithm(_fixupMaybeUint8Array(signature), _fixupMaybeUint8Array(data), keyTag, algorithm !== null && algorithm !== void 0 ? algorithm : 'SHA512withRSA'),
    getPublicKey: (keyTag) => RNRSAKeychain.getPublicKey(keyTag),
    getPublicKeyEd: (keyTag) => RNRSAKeychain.getPublicKeyEd(keyTag),
    getPublicKeyDER: (keyTag) => RNRSAKeychain.getPublicKeyDER(keyTag),
    getPublicKeyRSA: (keyTag) => RNRSAKeychain.getPublicKeyRSA(keyTag),
    getAllKeys: () => RNRSAKeychain.getAllKeys(),
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
