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
    /**
     * Generate RSA key pair with default 2048-bit key size
     * @param keyTag - Key tag identifier
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generate: (keyTag: string, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    /**
     * Generate RSA key pair with specified key size
     * @param keyTag - Key tag identifier
     * @param keySize - Key size in bits
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generateKeys: (keyTag: string, keySize: number, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    /**
     * Generate EC (P-256) key pair
     * @param keyTag - Key tag identifier
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generateEC: (keyTag: string, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    /**
     * Generate Ed25519 key pair
     * @param keyTag - Key tag identifier
     * @param synchronizable - Whether key should be synchronizable across devices
     * @param label - Optional label for the key
     * @returns Promise<PublicKey> - Generated public key
     */
    generateEd: (keyTag: string, synchronizable?: boolean, label?: string) => Promise<PublicKey>;
    /**
     * Generate Certificate Signing Request (CSR)
     * @param keyTag - Key tag identifier
     * @param CN - Common Name for the certificate
     * @param signature - Signature algorithm
     * @returns Promise<CSRKey> - Generated CSR
     */
    generateCSR: (keyTag: string, CN: string, signature?: TypeCrypto) => Promise<CSRKey>;
    /**
     * Generate CSR with EC key
     * @param cn - Common Name for the certificate
     * @param keyTag - Key tag identifier
     * @param keySize - Key size in bits
     * @returns Promise<PublicKey & CSRKey> - Generated public key and CSR
     */
    generateCSRWithEC: (cn: string, keyTag: string, keySize: number) => Promise<PublicKey & CSRKey>;
    /**
     * Delete private key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<boolean> - True if key was deleted successfully
     */
    deletePrivateKey: (keyTag: string) => Promise<boolean>;
    /**
     * Update private key label
     * @param keyTag - Key tag identifier
     * @param label - New label for the key
     * @returns Promise<boolean> - True if key was updated successfully
     */
    updatePrivateKey: (keyTag: string, label: string) => Promise<boolean>;
    /**
     * Encrypt data (non-64 version - handles raw strings/Uint8Arrays)
     * @param data - Raw string OR Uint8Array to encrypt (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded encrypted data
     */
    encrypt: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Decrypt data (non-64 version - returns raw string)
     * @param data - Raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Decrypted raw string
     */
    decrypt: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Encrypt data (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded encrypted data
     */
    encrypt64: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Decrypt data (64 version - handles base64 data)
     * @param data - Base64-encoded encrypted data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded decrypted data
     */
    decrypt64: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Sign data (non-64 version - handles raw strings/Uint8Arrays)
     * @param data - Raw string OR Uint8Array to sign (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded signature
     */
    sign: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Sign data with algorithm (non-64 version - handles raw strings/Uint8Arrays)
     * @param data - Raw string OR Uint8Array to sign (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<string> - Base64-encoded signature
     */
    signWithAlgorithm: (data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<string>;
    /**
     * Sign data (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<string> - Base64-encoded signature
     */
    sign64: (data: string | Uint8Array, keyTag: string) => Promise<string>;
    /**
     * Sign data with algorithm (64 version - handles base64 data)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
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
     * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param message - Original message: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param publicKey - Ed25519 public key: raw string OR Uint8Array (will be base64 encoded automatically)
     * @returns Promise<boolean> - True if signature is valid
     */
    verifyEd: (signature: string | Uint8Array, message: string | Uint8Array, publicKey: string | Uint8Array) => Promise<boolean>;
    /**
     * Verify signature (non-64 version - handles raw strings/Uint8Arrays)
     * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param data - Original data: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @returns Promise<boolean> - True if signature is valid
     */
    verify: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string) => Promise<boolean>;
    /**
     * Verify signature with algorithm (non-64 version - handles raw strings/Uint8Arrays)
     * @param signature - Signature: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param data - Original data: raw string OR Uint8Array (will be base64 encoded automatically)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<boolean> - True if signature is valid
     */
    verifyWithAlgorithm: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<boolean>;
    /**
     * Verify signature (64 version - handles base64 data)
     * @param signature - Base64-encoded signature string OR Uint8Array (passed to native code as-is)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @returns Promise<boolean> - True if signature is valid
     */
    verify64: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string) => Promise<boolean>;
    /**
     * Verify signature with algorithm (64 version - handles base64 data)
     * @param signature - Base64-encoded signature string OR Uint8Array (passed to native code as-is)
     * @param data - Base64-encoded data string OR Uint8Array (passed to native code as-is)
     * @param keyTag - Key tag identifier
     * @param algorithm - Signature algorithm (default: SHA512withRSA)
     * @returns Promise<boolean> - True if signature is valid
     */
    verify64WithAlgorithm: (signature: string | Uint8Array, data: string | Uint8Array, keyTag: string, algorithm?: TypeCrypto) => Promise<boolean>;
    /**
     * Get public key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - Public key
     */
    getPublicKey: (keyTag: string) => Promise<PublicKey>;
    /**
     * Get Ed25519 public key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - Ed25519 public key
     */
    getPublicKeyEd: (keyTag: string) => Promise<PublicKey>;
    /**
     * Get public key in DER format from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - Public key in DER format
     */
    getPublicKeyDER: (keyTag: string) => Promise<PublicKey>;
    /**
     * Get RSA public key from keychain
     * @param keyTag - Key tag identifier
     * @returns Promise<PublicKey> - RSA public key
     */
    getPublicKeyRSA: (keyTag: string) => Promise<PublicKey>;
    /**
     * Get all keys from keychain
     * @returns Promise<KeychainItem[]> - Array of all keychain items
     */
    getAllKeys: () => Promise<KeychainItem[]>;
    /**
     * Delete all keys from keychain
     * @returns Promise<boolean> - True if all keys were deleted successfully
     */
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
