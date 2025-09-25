import { RSAKeychain } from 'react-native-rsa-native';

const deleteIndividualKeysDemo = async () => {
  try {
    console.log('deleteIndividualKeysDemo start');

    // Start from completely empty state
    await RSAKeychain.deleteAllKeys();
    let allKeys = await RSAKeychain.getAllKeys();
    if (allKeys.length > 0) {
      console.log(
        `Expected 0 keys after initial cleanup, got ${allKeys.length}`,
      );
      return false;
    }

    // Add all key types
    await RSAKeychain.generate('test_rsa2048', false, 'Test RSA 2048');
    await RSAKeychain.generateKeys(
      'test_rsa4096',
      4096,
      false,
      'Test RSA 4096',
    );
    await RSAKeychain.generateEC('test_p256', false, 'Test P256');
    await RSAKeychain.generateEd('test_ed25519', false, 'Test Ed25519');

    // Verify all keys exist
    allKeys = await RSAKeychain.getAllKeys();
    const validKeys = allKeys.filter(k => k.tag && k.tag.startsWith('test_'));
    if (validKeys.length !== 4) {
      console.log(`Expected 4 keys after generation, got ${validKeys.length}`);
      return false;
    }

    // Delete each key individually in specified order: RSA first, Ed25519 second, EC last

    // Delete RSA keys first
    await RSAKeychain.deletePrivateKey('test_rsa2048');
    allKeys = await RSAKeychain.getAllKeys();
    if (!allKeys.some(k => k.tag === 'test_rsa4096')) {
      console.log(
        'test_rsa4096 should still exist after deleting test_rsa2048',
      );
      return false;
    }
    if (!allKeys.some(k => k.tag === 'test_ed25519')) {
      console.log(
        'test_ed25519 should still exist after deleting test_rsa2048',
      );
      return false;
    }
    if (!allKeys.some(k => k.tag === 'test_p256')) {
      console.log('test_p256 should still exist after deleting test_rsa2048');
      return false;
    }

    await RSAKeychain.deletePrivateKey('test_rsa4096');
    allKeys = await RSAKeychain.getAllKeys();
    if (!allKeys.some(k => k.tag === 'test_ed25519')) {
      console.log(
        'test_ed25519 should still exist after deleting test_rsa4096',
      );
      return false;
    }
    if (!allKeys.some(k => k.tag === 'test_p256')) {
      console.log('test_p256 should still exist after deleting test_rsa4096');
      return false;
    }

    // Delete Ed25519 second
    await RSAKeychain.deletePrivateKey('test_ed25519');
    allKeys = await RSAKeychain.getAllKeys();
    if (!allKeys.some(k => k.tag === 'test_p256')) {
      console.log('test_p256 should still exist after deleting test_ed25519');
      return false;
    }

    // Delete EC last
    await RSAKeychain.deletePrivateKey('test_p256');

    // Verify all keys deleted
    allKeys = await RSAKeychain.getAllKeys();
    if (allKeys.length !== 0) {
      console.log(
        `Expected 0 keys after individual deletions, got ${allKeys.length}`,
      );
      console.log(
        'Remaining keys:',
        allKeys.map(k => ({ tag: k.tag, type: k.type })),
      );
      return false;
    }

    console.log('deleteIndividualKeysDemo passed');
    return true;
  } catch (e) {
    console.log('deleteIndividualKeysDemo failed:', e);
    return false;
  }
};

export default deleteIndividualKeysDemo;
