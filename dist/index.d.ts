declare const RNRSAKeychain: any, RNRSA: any;
export interface PublicKey {
    public: string;
}
export interface CSRKey {
    csr: string;
}
export interface KeyPair extends PublicKey {
    private: string;
}
export type TypeCrypto = 'SHA256withRSA' | 'SHA512withRSA' | 'SHA1withRSA' | 'SHA256withECDSA' | 'SHA512withECDSA' | 'SHA1withECDSA';
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
export declare const RSA: {
    generate: () => Promise<KeyPair>;
    generateKeys: (keySize: number) => Promise<KeyPair>;
    encrypt: (data: string, key: string) => Promise<string>;
    decrypt: (data: string, key: string) => Promise<string>;
    encrypt64: (data: string, key: string) => Promise<string>;
    decrypt64: (data: string, key: string) => Promise<string>;
    sign: (data: string, key: string) => Promise<string>;
    signWithAlgorithm: (data: string, key: string, signature?: TypeCrypto) => Promise<string>;
    sign64: (data: string, key: string) => Promise<string>;
    sign64WithAlgorithm: (data: string, key: string, signature?: TypeCrypto) => Promise<string>;
    verify: (signature: string, data: string, key: string) => Promise<boolean>;
    verifyWithAlgorithm: (signature: string, data: string, key: string, algorithm?: TypeCrypto) => Promise<boolean>;
    verify64: (signature: string, data: string, key: string) => Promise<boolean>;
    verify64WithAlgorithm: (signature: string, data: string, key: string, algorithm?: TypeCrypto) => Promise<boolean>;
    SHA256withRSA: any;
    SHA512withRSA: any;
    SHA1withRSA: any;
    SHA256withECDSA: any;
    SHA512withECDSA: any;
    SHA1withECDSA: any;
};
export declare const RSAKeychain: {
    generate: (keyTag: string, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    generateKeys: (keyTag: string, keySize: number, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    generateEC: (keyTag: string, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    generateEd: (keyTag: string, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    generateCSR: (keyTag: string, CN: string, signature?: TypeCrypto) => Promise<CSRKey>;
    generateCSRWithEC: (cn: string, keyTag: string, keySize: number) => Promise<PublicKey & CSRKey>;
    deletePrivateKey: (keyTag: string) => Promise<boolean>;
    updatePrivateKey: (keyTag: string, label: string) => Promise<boolean>;
    encrypt: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    decrypt: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    encrypt64: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    decrypt64: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    sign: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    signWithAlgorithm: (data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<string>;
    sign64: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Sign data with algorithm (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<string> - Base64-encoded signature
     */
    sign64WithAlgorithm: (data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<string>;
    /**
     * Sign a message with Ed25519 private key from keychain
     * @param message - Message to sign: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<Uint8Array> - 64-byte Ed25519 signature
     */
    signEd: (message: string | Uint8Array, keyTag: string) => Promise<Uint8Array>;
    /**
     * Verify Ed25519 signature
     * @param signature - Signature: string OR Uint8Array (will be base64 encoded automatically)
     * @param message - Original message: string OR Uint8Array (will be base64 encoded automatically)
     * @param publicKey - Ed25519 public key: base64 string OR Uint8Array (will be base64 encoded automatically)
     * @returns Promise<boolean> - True if signature is valid
     */
    verifyEd: (signature: string | Uint8Array, message: string | Uint8Array, publicKey: string | Uint8Array) => Promise<boolean>;
    verify: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string) => Promise<boolean>;
    verifyWithAlgorithm: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<boolean>;
    verify64: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string) => Promise<boolean>;
    /**
     * Verify signature with algorithm (64 version - handles base64 data)
     * @param signature - Signature: base64 string OR Uint8Array (will be base64 encoded automatically)
     * @param data - Base64-encoded data string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<boolean> - True if signature is valid
     */
    verify64WithAlgorithm: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<boolean>;
    getPublicKey: (keyTag: string) => Promise<PublicKey>;
    getPublicKeyEd: (keyTag: string) => Promise<PublicKey>;
    getPublicKeyDER: (keyTag: string) => Promise<PublicKey>;
    getPublicKeyRSA: (keyTag: string) => Promise<PublicKey>;
    getAllKeys: () => Promise<KeychainItem[]>;
    deleteAllKeys: () => Promise<boolean>;
    SHA256withRSA: any;
    SHA512withRSA: any;
    SHA1withRSA: any;
    SHA256withECDSA: any;
    SHA512withECDSA: any;
    SHA1withECDSA: any;
};
export { RNRSAKeychain, RNRSA };
export default RNRSA;
