//
//  RNRSASwift.swift
//  test
//

//#if canImport(React)
//import React
//#endif
import Foundation
import CommonCrypto

@objc(RNRSAKeychain)
class RNRSAKeychain: NSObject {

    @objc
    static
    func requiresMainQueueSetup() -> Bool {
      return false
    }
    
    @objc
    func constantsToExport() -> [AnyHashable : Any]! {
        return[
            "SHA256withRSA": "SHA256withRSA",
            "SHA512withRSA": "SHA512withRSA",
            "SHA1withRSA"  : "SHA1withRSA",
            "SHA256withECDSA" : "SHA256withECDSA",
            "SHA512withECDSA" : "SHA512withECDSA",
            "SHA1withECDSA"   : "SHA1withECDSA"
        ]
    }
    
    // MARK: - Helper Methods
    
    private static func getPrivateKey(keyTag: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            return result as! SecKey?
        }
        return nil
    }
    
    private static func getKeyData(key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        return SecKeyCopyExternalRepresentation(key, &error) as Data?
    }
    
    private static func getSignatureAlgorithm(_ algorithm: String) -> SecKeyAlgorithm {
        switch algorithm {
        case "SHA256withRSA":
            return .rsaSignatureMessagePKCS1v15SHA256
        case "SHA512withRSA":
            return .rsaSignatureMessagePKCS1v15SHA512
        case "SHA1withRSA":
            return .rsaSignatureMessagePKCS1v15SHA1
        default:
            return .rsaSignatureMessagePKCS1v15SHA512
        }
    }
    
    private static func formatPublicKeyDER(_ keyData: Data) -> String {
        let convertedData = convertToX509EncodedKey(keyData)
        return formatPEM(convertedData, tag: "PUBLIC")
    }
    
    private static func formatPEM(_ keyData: Data, tag: String) -> String {
        let base64String = keyData.base64EncodedString()
        return "-----BEGIN \(tag) KEY-----\n\(base64String)\n-----END \(tag) KEY-----"
    }
    
    private static func convertToX509EncodedKey(_ rsaPublicKeyData: Data) -> Data {
        let algorithmIdentifierForRSAEncryption: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
        
        var derEncodedKeyBytes = [UInt8](rsaPublicKeyData)
        
        derEncodedKeyBytes.insert(0x00, at: 0)
        derEncodedKeyBytes.insert(contentsOf: lengthField(of: derEncodedKeyBytes), at: 0)
        derEncodedKeyBytes.insert(0x03, at: 0)
        
        derEncodedKeyBytes.insert(contentsOf: algorithmIdentifierForRSAEncryption, at: 0)
        
        derEncodedKeyBytes.insert(contentsOf: lengthField(of: derEncodedKeyBytes), at: 0)
        derEncodedKeyBytes.insert(0x30, at: 0)
        
        return Data(derEncodedKeyBytes)
    }
    
    private static func lengthField(of valueField: [UInt8]) -> [UInt8] {
        var length = valueField.count
        
        if length < 128 {
            return [UInt8(length)]
        }
        
        let lengthBytesCount = Int((log2(Double(length)) / 8) + 1)
        let firstLengthFieldByte = UInt8(128 + lengthBytesCount)
        
        var lengthField: [UInt8] = []
        for _ in 0..<lengthBytesCount {
            let lengthByte = UInt8(length & 0xff)
            lengthField.insert(lengthByte, at: 0)
            length = length >> 8
        }
        
        lengthField.insert(firstLengthFieldByte, at: 0)
        return lengthField
    }
    
    // MARK: - Key Generation Methods
    
    @objc
    func generate(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        generateKeys(keyTag, keySize: 2048, resolver: resolve, rejecter: reject)
    }
    
    @objc
    func generateKeys(_ keyTag: String, keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let privateKeyParameters: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecReturnRef as String: true,
            kSecPrivateKeyAttrs as String: privateKeyParameters
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            reject("KEY_GENERATION_ERROR", "Failed to generate key pair", nil)
            return
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = Self.getKeyData(key: publicKey) else {
            reject("PUBLIC_KEY_ERROR", "Failed to get public key", nil)
            return
        }
        
        let publicKeyDER = Self.formatPublicKeyDER(publicKeyData)
        resolve(["public": publicKeyDER])
    }
    
    @objc
    func generateEC(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let privateKeyParameters: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecReturnRef as String: true,
            kSecPrivateKeyAttrs as String: privateKeyParameters
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            reject("KEY_GENERATION_ERROR", "Failed to generate EC key pair", nil)
            return
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = Self.getKeyData(key: publicKey) else {
            reject("PUBLIC_KEY_ERROR", "Failed to get public key", nil)
            return
        }
        
        let publicKeyPEM = Self.formatPEM(publicKeyData, tag: "PUBLIC")
        resolve(["public": publicKeyPEM])
    }
    
    // MARK: - Signing Methods
    
    @objc
    func sign(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        signWithAlgorithm(message, keyTag: keyTag, withAlgorithm: "SHA512withRSA", resolver: resolve, rejecter: reject)
    }
    
    @objc
    func signWithAlgorithm(_ message: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag) else {
            reject("PRIVATE_KEY_NOT_FOUND", "Private key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let messageData = message.data(using: .utf8) else {
            reject("MESSAGE_ENCODING_ERROR", "Failed to encode message", nil)
            return
        }
        
        let algorithm = Self.getSignatureAlgorithm(withAlgorithm)
        var error: Unmanaged<CFError>?
        
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, messageData as CFData, &error) else {
            reject("SIGNING_ERROR", "Failed to sign message", nil)
            return
        }
        
        let signatureString = (signature as Data).base64EncodedString()
        resolve(signatureString)
    }
    
    @objc
    func sign64(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        sign64WithAlgorithm(message, keyTag: keyTag, withAlgorithm: "SHA512withRSA", resolver: resolve, rejecter: reject)
    }
    
    @objc
    func sign64WithAlgorithm(_ message: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag) else {
            reject("PRIVATE_KEY_NOT_FOUND", "Private key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let messageData = Data(base64Encoded: message) else {
            reject("MESSAGE_DECODING_ERROR", "Failed to decode base64 message", nil)
            return
        }
        
        let algorithm = Self.getSignatureAlgorithm(withAlgorithm)
        var error: Unmanaged<CFError>?
        
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, messageData as CFData, &error) else {
            reject("SIGNING_ERROR", "Failed to sign message", nil)
            return
        }
        
        let signatureString = (signature as Data).base64EncodedString()
        resolve(signatureString)
    }
    
    // MARK: - Verification Methods
    
    @objc
    func verify(_ signature: String, withMessage: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        verifyWithAlgorithm(signature, withMessage: withMessage, keyTag: keyTag, withAlgorithm: "SHA512withRSA", resolver: resolve, rejecter: reject)
    }
    
    @objc
    func verifyWithAlgorithm(_ signature: String, withMessage: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            reject("KEY_NOT_FOUND", "Key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let messageData = withMessage.data(using: .utf8),
              let signatureData = Data(base64Encoded: signature) else {
            reject("DATA_ENCODING_ERROR", "Failed to encode data", nil)
            return
        }
        
        let algorithm = Self.getSignatureAlgorithm(withAlgorithm)
        var error: Unmanaged<CFError>?
        
        let isValid = SecKeyVerifySignature(publicKey, algorithm, messageData as CFData, signatureData as CFData, &error)
        
        if isValid {
            resolve(true)
        } else {
            reject("VERIFICATION_FAILED", "Signature verification failed", nil)
        }
    }
    
    @objc
    func verify64(_ signature: String, withMessage: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        verify64WithAlgorithm(signature, withMessage: withMessage, keyTag: keyTag, withAlgorithm: "SHA512withRSA", resolver: resolve, rejecter: reject)
    }
    
    @objc
    func verify64WithAlgorithm(_ signature: String, withMessage: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            reject("KEY_NOT_FOUND", "Key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let messageData = Data(base64Encoded: withMessage),
              let signatureData = Data(base64Encoded: signature) else {
            reject("DATA_DECODING_ERROR", "Failed to decode base64 data", nil)
            return
        }
        
        let algorithm = Self.getSignatureAlgorithm(withAlgorithm)
        var error: Unmanaged<CFError>?
        
        let isValid = SecKeyVerifySignature(publicKey, algorithm, messageData as CFData, signatureData as CFData, &error)
        
        if isValid {
            resolve(true)
        } else {
            reject("VERIFICATION_FAILED", "Signature verification failed", nil)
        }
    }
    
    // MARK: - Encryption/Decryption Methods
    
    @objc
    func encrypt(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            reject("KEY_NOT_FOUND", "Key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let messageData = message.data(using: .utf8) else {
            reject("MESSAGE_ENCODING_ERROR", "Failed to encode message", nil)
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, messageData as CFData, &error) else {
            reject("ENCRYPTION_ERROR", "Failed to encrypt message", nil)
            return
        }
        
        let encryptedString = (encryptedData as Data).base64EncodedString()
        resolve(encryptedString)
    }
    
    @objc
    func decrypt(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag) else {
            reject("PRIVATE_KEY_NOT_FOUND", "Private key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let encryptedData = Data(base64Encoded: message) else {
            reject("MESSAGE_DECODING_ERROR", "Failed to decode encrypted message", nil)
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, encryptedData as CFData, &error) else {
            reject("DECRYPTION_ERROR", "Failed to decrypt message", nil)
            return
        }
        
        guard let decryptedString = String(data: decryptedData as Data, encoding: .utf8) else {
            reject("STRING_ENCODING_ERROR", "Failed to encode decrypted data as string", nil)
            return
        }
        
        resolve(decryptedString)
    }
    
    @objc
    func encrypt64(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            reject("KEY_NOT_FOUND", "Key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let messageData = Data(base64Encoded: message) else {
            reject("MESSAGE_DECODING_ERROR", "Failed to decode base64 message", nil)
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, messageData as CFData, &error) else {
            reject("ENCRYPTION_ERROR", "Failed to encrypt message", nil)
            return
        }
        
        let encryptedString = (encryptedData as Data).base64EncodedString()
        resolve(encryptedString)
    }
    
    @objc
    func decrypt64(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag) else {
            reject("PRIVATE_KEY_NOT_FOUND", "Private key not found for tag: \(keyTag)", nil)
            return
        }
        
        guard let encryptedData = Data(base64Encoded: message) else {
            reject("MESSAGE_DECODING_ERROR", "Failed to decode encrypted message", nil)
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, encryptedData as CFData, &error) else {
            reject("DECRYPTION_ERROR", "Failed to decrypt message", nil)
            return
        }
        
        let decryptedString = (decryptedData as Data).base64EncodedString()
        resolve(decryptedString)
    }
    
    // MARK: - Public Key Retrieval Methods
    
    @objc
    func getPublicKey(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = Self.getKeyData(key: publicKey) else {
            reject("PUBLIC_KEY_ERROR", "Failed to get public key for tag: \(keyTag)", nil)
            return
        }
        
        let publicKeyPEM = Self.formatPEM(publicKeyData, tag: "PUBLIC")
        resolve(["public": publicKeyPEM])
    }
    
    @objc
    func getPublicKeyDER(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = Self.getKeyData(key: publicKey) else {
            reject("PUBLIC_KEY_ERROR", "Failed to get public key for tag: \(keyTag)", nil)
            return
        }
        
        let publicKeyDER = Self.formatPublicKeyDER(publicKeyData)
        resolve(["public": publicKeyDER])
    }
    
    @objc
    func getPublicKeyRSA(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = Self.getKeyData(key: publicKey) else {
            reject("PUBLIC_KEY_ERROR", "Failed to get public key for tag: \(keyTag)", nil)
            return
        }
        
        let publicKeyPEM = Self.formatPEM(publicKeyData, tag: "RSA PUBLIC")
        resolve(["public": publicKeyPEM])
    }
    
    // MARK: - Key Management Methods
    
    @objc
    func deletePrivateKey(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        resolve(status == errSecSuccess)
    }
    
    // MARK: - CSR Generation Methods
    
    @objc
    func generateCSR(_ keyTag: String, CN: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        guard let privateKey = Self.getPrivateKey(keyTag: keyTag),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = Self.getKeyData(key: publicKey) else {
            reject("KEY_NOT_FOUND", "Key not found for tag: \(keyTag)", nil)
            return
        }
        
        let keyAlgorithm = Self.getKeyAlgorithm(withAlgorithm)
        let csr = CertificateSigningRequest(commonName: CN, organizationName: nil, organizationUnitName: nil, countryName: nil, stateOrProvinceName: nil, localityName: nil, keyAlgorithm: keyAlgorithm)
        
        guard let csrString = csr.buildCSRAndReturnString(publicKeyData, privateKey: privateKey) else {
            reject("CSR_GENERATION_ERROR", "Failed to generate CSR", nil)
            return
        }
        
        resolve(["csr": csrString])
    }
    
    @objc
    func generateCSRWithEC(_ CN: String, keyTag: String, keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        generateEC(keyTag, resolver: { result in
            guard let keyResult = result as? [String: String],
                  let publicKey = keyResult["public"] else {
                reject("EC_KEY_GENERATION_ERROR", "Failed to generate EC key", nil)
                return
            }
            
            self.generateCSR(keyTag, CN: CN, withAlgorithm: "SHA256withECDSA", resolver: { csrResult in
                guard let csrDict = csrResult as? [String: String],
                      let csr = csrDict["csr"] else {
                    reject("CSR_GENERATION_ERROR", "Failed to generate CSR", nil)
                    return
                }
                resolve(["csr": csr, "public": publicKey])
            }, rejecter: reject)
        }, rejecter: reject)
    }
    
    private static func getKeyAlgorithm(_ algorithm: String) -> KeyAlgorithm {
        switch algorithm {
        case "SHA256withRSA":
            return .rsa(signatureType: .sha256)
        case "SHA512withRSA":
            return .rsa(signatureType: .sha512)
        case "SHA1withRSA":
            return .rsa(signatureType: .sha1)
        case "SHA256withECDSA":
            return .ec(signatureType: .sha256)
        case "SHA512withECDSA":
            return .ec(signatureType: .sha512)
        case "SHA1withECDSA":
            return .ec(signatureType: .sha1)
        default:
            return .rsa(signatureType: .sha512)
        }
    }
    
    // MARK: - Key Enumeration Methods (Already Implemented)
    
    @objc
    func getAllKeys(_ resolver: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        var keysInfo: [[String: Any]] = []

        if status == errSecSuccess,
           let items = result as? [[String: Any]] {
            for item in items {
                let keyTypeNumber = item[kSecAttrKeyType as String] as? NSNumber
                let keyTypeInt = keyTypeNumber?.intValue ?? 0
                let keyTypeString: String
                switch keyTypeInt {
                case 42: // kSecAttrKeyTypeRSA
                    keyTypeString = "RSA"
                case 73: // kSecAttrKeyTypeECSECPrimeRandom
                    keyTypeString = "EC"
                case 77: // kSecAttrKeyTypeEd25519
                    keyTypeString = "Ed25519"
                default:
                    keyTypeString = "Type \(keyTypeInt)"
                }
                let keyClassNumber = item[kSecAttrKeyClass as String] as? NSNumber
                let keyClassString: String
                let keyPublicKey: String
                if let keyClass = keyClassNumber {
                    switch keyClass.intValue {
                    case 0: // kSecAttrKeyClassPublic
                        keyClassString = "Public"
                    case 1: // kSecAttrKeyClassPrivate
                        keyClassString = "Private"
                    case 2: // kSecAttrKeyClassSymmetric
                        keyClassString = "Symmetric"
                    default:
                        keyClassString = "Unknown (\(keyClass.intValue))"
                    }
                    if let keyRef = item[kSecValueRef as String] {
                      var publicKeyData: Data?

                      switch keyClass.intValue {
                      case 0:
                          if let secKey = keyRef as! SecKey? {
                              var error: Unmanaged<CFError>?
                              if let keyData = SecKeyCopyExternalRepresentation(secKey, &error) {
                                  publicKeyData = keyData as Data
                              }
                          }
                        break
                      case 1:
                          if let privateKey = keyRef as! SecKey? {
                              if let publicKey = SecKeyCopyPublicKey(privateKey) {
                                  var error: Unmanaged<CFError>?
                                  if let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) {
                                      publicKeyData = keyData as Data
                                  }
                              }
                          }
                        break
                      default:
                        break
                      }

                      if let data = publicKeyData {
                          keyPublicKey = data.base64EncodedString()
                      } else {
                          keyPublicKey = ""
                      }
                  } else {
                      keyPublicKey = ""
                  }
                } else {
                    keyClassString = "Unknown"
                    keyPublicKey = ""
                }

                let keyAppTag: String
                if let appTag = item[kSecAttrApplicationTag as String] as? Data {
                    if let tagString = String(data: appTag, encoding: .utf8) {
                        keyAppTag = tagString
                    } else {
                        // Fallback for binary data - use hex representation
                        keyAppTag = appTag.map { String(format: "%02x", $0) }.joined()
                    }
                } else {
                    keyAppTag = ""
                }
                let keyLabel: String
                if let labelData = item[kSecAttrLabel as String] as? Data {
                    keyLabel = String(data: labelData, encoding: .utf8) ?? "Unknown"
                } else {
                    keyLabel = ""
                }
                let keyAccessControl: String
                if let accessControl = item[kSecAttrAccessControl as String] {
                    keyAccessControl = String(describing: accessControl)
                } else {
                    keyAccessControl = ""
                }

                let info: [String: Any] = [
                    "class": keyClassString,
                    "type": keyTypeString,
                    "size": item[kSecAttrKeySizeInBits as String] as? Int ?? 0,
                    "public": keyPublicKey,
                    "extractable": (item[kSecAttrIsExtractable as String] as? NSNumber)?.boolValue ?? false,
                    "tag": keyAppTag,
                    "label": keyLabel,
                    "syncronizable": (item[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue ?? false,
                    "accessControl": keyAccessControl,
                ];
                keysInfo.append(info);
            }

        } else if (status == errSecItemNotFound) {
            resolver(keysInfo)
            return
        }
        guard status == errSecSuccess else {
            reject("SEC_KEY_ENUM_ERROR", "Failed to enumerate keys: \(status)", nil)
            return
        }
        resolver(keysInfo)
    }

    @objc
    func deleteAllKeys(_ resolver: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey
        ]
        let status = SecItemDelete(query as CFDictionary)
        resolver(status == errSecSuccess)
    }
}

