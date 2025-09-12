//
//  RNECRSASwift.m
//  RNECRSA
//

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RNRSAKeychain, NSObject)

RCT_EXTERN_METHOD(generateKeys:(NSString *)keyTag keySize:(int)keySize synchronizable:(BOOL)synchronizable label:(NSString *)label resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateCSR:(NSString *)keyTag CN:(NSString *)CN withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateCSRWithEC:(NSString *)CN keyTag:(NSString *)keyTag keySize:(int)keySize resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateEC:(NSString *)keyTag synchronizable:(BOOL)synchronizable label:(NSString *)label resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateEd:(NSString *)keyTag synchronizable:(BOOL)synchronizable label:(NSString *)label resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sign64WithAlgorithm:(NSString *)message keyTag:(NSString *)keyTag withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signEd:(NSString *)message keyTag:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyEd:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyDER:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyRSA:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKey:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verify64WithAlgorithm:(NSString *)signature withMessage:(NSString *)withMessage keyTag:(NSString *)keyTag withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyEd:(NSString *)signature withMessage:(NSString *)withMessage withPublicKey:(NSString *)publicKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deletePrivateKey:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt64:(NSString *)message keyTag:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(decrypt64:(NSString *)message keyTag:(NSString *)keyTag resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(updatePrivateKey:(NSString *)keyTag label:(NSString *)label resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getAllKeys:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deleteAllKeys:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

@end







