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
        return await RNRSA.decrypt64(btoa(data), key);
    },
    encrypt64: (data, key) => RNRSA.encrypt64(data, key),
    decrypt64: (data, key) => RNRSA.decrypt64(data, key),
    sign: async (data, key) => {
        return await RNRSA.sign64WithAlgorithm(btoa(data), key, 'SHA512withRSA');
    },
    signWithAlgorithm: async (data, key, signature) => {
        return await RNRSA.sign64WithAlgorithm(btoa(data), key, signature || 'SHA512withRSA');
    },
    sign64: (data, key) => RNRSA.sign64WithAlgorithm(data, key, 'SHA512withRSA'),
    sign64WithAlgorithm: (data, key, signature) => RNRSA.sign64WithAlgorithm(data, key, signature),
    verify: async (signature, data, key) => RNRSA.verify64WithAlgorithm(btoa(signature), btoa(data), key, 'SHA512withRSA'),
    verifyWithAlgorithm: async (signature, data, key, algorithm) => RNRSA.verify64WithAlgorithm(btoa(signature), btoa(data), key, algorithm || 'SHA512withRSA'),
    verify64: (signature, data, key) => RNRSA.verify64WithAlgorithm(signature, data, key, 'SHA512withRSA'),
    verify64WithAlgorithm: (signature, data, key, algorithm) => RNRSA.verify64WithAlgorithm(signature, data, key, algorithm),
    SHA256withRSA: RNRSA.SHA256withRSA,
    SHA512withRSA: RNRSA.SHA512withRSA,
    SHA1withRSA: RNRSA.SHA1withRSA,
    SHA256withECDSA: RNRSA.SHA256withECDSA,
    SHA512withECDSA: RNRSA.SHA512withECDSA,
    SHA1withECDSA: RNRSA.SHA1withECDSA,
};
exports.RSAKeychain = {
    generate: (keyTag) => RNRSAKeychain.generateKeys(keyTag, 2048),
    generateKeys: (keyTag, keySize) => RNRSAKeychain.generateKeys(keyTag, keySize),
    generateEC: (keyTag) => RNRSAKeychain.generateEC(keyTag),
    generateCSR: (keyTag, CN, signature) => RNRSAKeychain.generateCSR(keyTag, CN, signature || 'SHA512withRSA'),
    generateCSRWithEC: (cn, keyTag, keySize) => RNRSAKeychain.generateCSRWithEC(cn, keyTag, keySize),
    deletePrivateKey: (keyTag) => RNRSAKeychain.deletePrivateKey(keyTag),
    encrypt: async (data, keyTag) => {
        return await RNRSAKeychain.encrypt64(btoa(data), keyTag);
    },
    decrypt: async (data, keyTag) => {
        return await RNRSAKeychain.decrypt64(btoa(data), keyTag);
    },
    encrypt64: (data, keyTag) => RNRSAKeychain.encrypt64(data, keyTag),
    decrypt64: (data, keyTag) => RNRSAKeychain.decrypt64(data, keyTag),
    sign: async (data, keyTag) => {
        return await RNRSAKeychain.sign64WithAlgorithm(btoa(data), keyTag, 'SHA512withRSA');
    },
    signWithAlgorithm: async (data, keyTag, signature) => {
        return await RNRSAKeychain.sign64WithAlgorithm(btoa(data), keyTag, signature || 'SHA512withRSA');
    },
    sign64: (data, keyTag) => RNRSAKeychain.sign64WithAlgorithm(data, keyTag, 'SHA512withRSA'),
    sign64WithAlgorithm: (data, keyTag, signature) => RNRSAKeychain.sign64WithAlgorithm(data, keyTag, signature || 'SHA512withRSA'),
    verify: async (signature, data, keyTag) => RNRSAKeychain.verify64WithAlgorithm(btoa(signature), btoa(data), keyTag, 'SHA512withRSA'),
    verifyWithAlgorithm: async (signature, data, keyTag, algorithm) => RNRSAKeychain.verify64WithAlgorithm(btoa(signature), btoa(data), keyTag, algorithm || 'SHA512withRSA'),
    verify64: (signature, data, keyTag) => RNRSAKeychain.verify64WithAlgorithm(signature, data, keyTag, 'SHA512withRSA'),
    verify64WithAlgorithm: (signature, data, keyTag, algorithm) => RNRSAKeychain.verify64WithAlgorithm(signature, data, keyTag, algorithm || 'SHA512withRSA'),
    getPublicKey: (keyTag) => RNRSAKeychain.getPublicKey(keyTag),
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
exports.default = RNRSA;
