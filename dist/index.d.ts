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
    generate: (keyTag: string) => Promise<PublicKey>;
    generateKeys: (keyTag: string, keySize: number) => Promise<PublicKey>;
    generateEC: (keyTag: string) => Promise<PublicKey>;
    generateCSR: (keyTag: string, CN: string, signature?: TypeCrypto) => Promise<CSRKey>;
    generateCSRWithEC: (cn: string, keyTag: string, keySize: number) => Promise<PublicKey & CSRKey>;
    deletePrivateKey: (keyTag: string) => Promise<boolean>;
    encrypt: (data: string, keyTag: string) => Promise<string>;
    decrypt: (data: string, keyTag: string) => Promise<string>;
    encrypt64: (data: string, keyTag: string) => Promise<string>;
    decrypt64: (data: string, keyTag: string) => Promise<string>;
    sign: (data: string, keyTag: string) => Promise<string>;
    signWithAlgorithm: (data: string, keyTag: string, signature?: TypeCrypto) => Promise<string>;
    sign64: (data: string, keyTag: string) => Promise<string>;
    sign64WithAlgorithm: (data: string, keyTag: string, signature?: TypeCrypto) => Promise<string>;
    verify: (signature: string, data: string, keyTag: string) => Promise<boolean>;
    verifyWithAlgorithm: (signature: string, data: string, keyTag: string, algorithm?: TypeCrypto) => Promise<boolean>;
    verify64: (signature: string, data: string, keyTag: string) => Promise<boolean>;
    verify64WithAlgorithm: (signature: string, data: string, keyTag: string, algorithm?: TypeCrypto) => Promise<boolean>;
    getPublicKey: (keyTag: string) => Promise<PublicKey>;
    getPublicKeyDER: (keyTag: string) => Promise<PublicKey>;
    getPublicKeyRSA: (keyTag: string) => Promise<PublicKey>;
    getAllKeys: () => Promise<any[]>;
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
