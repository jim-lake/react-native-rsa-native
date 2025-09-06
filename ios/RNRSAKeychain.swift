//
//  RNRSASwift.swift
//  test
//

//#if canImport(React)
//import React
//#endif
import Foundation

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
    
    
    
    // generate key with default keysize - RSA - DER format
    @objc
    func generate(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        // with default alogo RSA
        let res = rsa_ec.generate(keySize: 2048)
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKeyDER()
            let keys = ["public": pub]
            resolve(keys)
            return
        }
        resolve(false)
        
    }
    
    // generate key with keysize - RSA - DER format
    @objc
    func generateKeys(_ keyTag: String, keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        // with default alogo RSA
        let res = rsa_ec.generate(keySize: keySize)
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKeyDER()
            let keys = ["public": pub]
            resolve(keys)
            return
        }
        resolve(false)
    }
    
    @objc
    func generateCSR(_ keyTag: String, CN: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let csr = rsa_ec.generateCSR(CN: CN, withAlgorithm: withAlgorithm)
        if(csr != nil){
            let keys = ["csr": csr]
            resolve(keys)
        }else {
            reject("not exist CSR", "error", nil)
        }
    }
    
    @objc
    func generateCSRWithEC(_ CN: String, keyTag: String, keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let res = rsa_ec.generateEC()
        let pub = rsa_ec.encodedPublicKey()
        let csr = rsa_ec.generateCSR(CN: CN, withAlgorithm: "SHA256withECDSA")
        if(csr != nil){
            let keys = ["csr": csr, "public": pub]
            resolve(keys)
        }else {
            reject("not exist CSR", "error", nil)
        }
    }
    
    @objc
    func generateEC(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let res = rsa_ec.generateEC()
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKey()
            let keys = ["public": pub]
            resolve(keys)
            return
        }
        resolve(false)
    }
    
    @objc
    func sign(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign(message: message, withAlgorithm: "SHA512withRSA", withEncodeOption: NSData.Base64EncodingOptions(rawValue: 0))
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func signWithAlgorithm(_ message: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign(message: message, withAlgorithm: withAlgorithm, withEncodeOption: NSData.Base64EncodingOptions(rawValue: 0))
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func sign64(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign64(b64message: message, withAlgorithm: "SHA512withRSA")
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func sign64WithAlgorithm(_ message: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign64(b64message: message, withAlgorithm: withAlgorithm)
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    // generate key with default keysize  - DER format
    @objc
    func getPublicKeyDER(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let pub = rsa_ec.encodedPublicKeyDER()
        if(pub == nil){
            reject("not exist public key", "error", nil)
        }else {
            let keys = ["public": pub]
            resolve(keys)
        }
    }
    
    // generate key with default keysize  - DER format
    @objc
    func getPublicKey(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let pub = rsa_ec.encodedPublicKey()
        if(pub == nil){
            reject("not exist public key", "error", nil)
        }else {
            let keys = ["public": pub]
            resolve(keys)
        }
    }
    
    // generate key with default keysize  - DER format
    @objc
    func getPublicKeyRSA(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let pub = rsa_ec.encodedPublicKeyRSA()
        if(pub == nil){
            reject("not exist public key", "error", nil)
        }else {
            let keys = ["public": pub]
            resolve(keys)
        }
    }
    
    @objc
    func verify(_ signature: String, withMessage: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify(encodedSignature: signature, withMessage: withMessage, withAlgorithm: "SHA512withRSA")
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verifyWithAlgorithm(_ signature: String, withMessage: String ,keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify(encodedSignature: signature, withMessage: withMessage, withAlgorithm: withAlgorithm)
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verify64(_ signature: String, withMessage: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify64(encodedSignature: signature, withMessage: withMessage, withAlgorithm: "SHA512withRSA")
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verify64WithAlgorithm(_ signature: String, withMessage: String ,keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify64(encodedSignature: signature, withMessage: withMessage, withAlgorithm: withAlgorithm)
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func deletePrivateKey(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let result = rsa_ec.deletePrivateKey()
        resolve(result)
    }
    
    
    @objc
    func decrypt(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.decrypt(message: message)
        resolve(msg)
    }
    
    @objc
    func encrypt(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.encrypt(message: message)
        resolve(msg)
    }
    
    @objc
    func decrypt64(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.decrypt64(message: message)
        resolve(msg)
    }
    
    @objc
    func encrypt64(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.encrypt64(message: message)
        resolve(msg)
    }
    
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

