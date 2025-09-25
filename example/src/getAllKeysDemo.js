import { RSAKeychain } from 'react-native-rsa-native';

const getAllKeysDemo = async () => {
  try {
    console.log('getAllKeysDemo start');
    
    // Clean up any existing keys
    await RSAKeychain.deleteAllKeys();
    
    const RSA_TAG = 'test_rsa_key';
    const EC_TAG = 'test_ec_key';
    const ED_TAG = 'test_ed_key';
    
    // Generate one key of each type
    const rsaKeys = await RSAKeychain.generate(RSA_TAG, false, 'Test RSA Key');
    const ecKeys = await RSAKeychain.generateEC(EC_TAG, true, 'Test EC Key');
    const edKeys = await RSAKeychain.generateEd(ED_TAG, false, 'Test Ed Key');
    
    // Get all keys and validate TypeScript interface compliance
    const allKeys = await RSAKeychain.getAllKeys();
    
    // Filter out keys with empty tags (iOS may return public key entries with empty tags)
    const validKeys = allKeys.filter(k => k.tag && k.tag.trim() !== '');
    
    if (validKeys.length !== 3) {
      console.log(`Expected 3 valid keys, got ${validKeys.length}`);
      return false;
    }
    
    // Validate each key conforms to KeychainItem interface
    for (const key of validKeys) {
      // Required string properties
      if (typeof key.class !== 'string') {
        console.log(`Key ${key.tag}: class must be string, got ${typeof key.class}`);
        return false;
      }
      if (typeof key.type !== 'string') {
        console.log(`Key ${key.tag}: type must be string, got ${typeof key.type}`);
        return false;
      }
      if (typeof key.public !== 'string') {
        console.log(`Key ${key.tag}: public must be string, got ${typeof key.public}`);
        return false;
      }
      if (typeof key.tag !== 'string') {
        console.log(`Key ${key.tag}: tag must be string, got ${typeof key.tag}`);
        return false;
      }
      if (typeof key.label !== 'string') {
        console.log(`Key ${key.tag}: label must be string, got ${typeof key.label}`);
        return false;
      }
      if (typeof key.accessControl !== 'string') {
        console.log(`Key ${key.tag}: accessControl must be string, got ${typeof key.accessControl}`);
        return false;
      }
      
      // Required number property
      if (typeof key.size !== 'number') {
        console.log(`Key ${key.tag}: size must be number, got ${typeof key.size}`);
        return false;
      }
      
      // Required boolean properties
      if (typeof key.extractable !== 'boolean') {
        console.log(`Key ${key.tag}: extractable must be boolean, got ${typeof key.extractable}`);
        return false;
      }
      if (typeof key.syncronizable !== 'boolean') {
        console.log(`Key ${key.tag}: syncronizable must be boolean, got ${typeof key.syncronizable}`);
        return false;
      }
    }
    
    // Validate specific key types and properties
    const rsaKey = validKeys.find(k => k.tag === RSA_TAG);
    const ecKey = validKeys.find(k => k.tag === EC_TAG);
    const edKey = validKeys.find(k => k.tag === ED_TAG);
    
    if (!rsaKey || !ecKey || !edKey) {
      console.log('Missing expected keys in getAllKeys result');
      return false;
    }
    
    // RSA key validation
    if (rsaKey.type !== 'RSA') {
      console.log(`RSA key type should be 'RSA', got '${rsaKey.type}'`);
      return false;
    }
    if (rsaKey.public !== rsaKeys.public) {
      console.log('RSA public key mismatch between generate and getAllKeys');
      return false;
    }
    if (rsaKey.publicEd25519 !== undefined) {
      console.log('RSA key should not have publicEd25519 property');
      return false;
    }
    
    // EC key validation
    if (ecKey.type !== 'EC') {
      console.log(`EC key type should be 'EC', got '${ecKey.type}'`);
      return false;
    }
    if (ecKey.public !== ecKeys.public) {
      console.log('EC public key mismatch between generate and getAllKeys');
      return false;
    }
    
    // Ed25519 key validation
    if (!edKey.publicEd25519) {
      console.log('Ed25519 key missing required publicEd25519 property');
      return false;
    }
    if (edKey.publicEd25519 !== edKeys.public) {
      console.log('Ed25519 public key mismatch between generate and getAllKeys');
      return false;
    }
    
    console.log('All TypeScript interface validations passed');
    await RSAKeychain.deleteAllKeys();
    
    return true;
  } catch (e) {
    console.log('getAllKeysDemo failed:', e);
    return false;
  }
};

export default getAllKeysDemo;
