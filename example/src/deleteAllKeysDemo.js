import { RSAKeychain } from 'react-native-rsa-native';

const deleteAllKeysDemo = async () => {
  try {
    console.log('deleteAllKeysDemo start');
    
    // Start from completely empty state
    await RSAKeychain.deleteAllKeys();
    let allKeys = await RSAKeychain.getAllKeys();
    if (allKeys.length > 0) {
      console.log(`Expected 0 keys after initial cleanup, got ${allKeys.length}`);
      return false;
    }
    
    // Add all key types
    await RSAKeychain.generate('test_rsa2048', false, 'Test RSA 2048');
    await RSAKeychain.generateKeys('test_rsa4096', 4096, false, 'Test RSA 4096');
    await RSAKeychain.generateEC('test_p256', false, 'Test P256');
    await RSAKeychain.generateEd('test_ed25519', false, 'Test Ed25519');
    
    // Verify all keys exist
    allKeys = await RSAKeychain.getAllKeys();
    const validKeys = allKeys.filter(k => k.tag && k.tag.startsWith('test_'));
    if (validKeys.length !== 4) {
      console.log(`Expected 4 keys after generation, got ${validKeys.length}`);
      return false;
    }
    
    // Delete all keys
    await RSAKeychain.deleteAllKeys();
    
    // Verify all keys deleted
    allKeys = await RSAKeychain.getAllKeys();
    if (allKeys.length !== 0) {
      console.log(`Expected 0 keys after deleteAllKeys, got ${allKeys.length}`);
      return false;
    }
    
    console.log('deleteAllKeysDemo passed');
    return true;
  } catch (e) {
    console.log('deleteAllKeysDemo failed:', e);
    return false;
  }
};

export default deleteAllKeysDemo;
