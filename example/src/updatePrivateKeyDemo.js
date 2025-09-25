import { RSAKeychain } from 'react-native-rsa-native';

const updatePrivateKeyDemo = async () => {
  try {
    console.log('updatePrivateKeyDemo start');
    const UPDATE_TAG = 'update_tag1';
    await RSAKeychain.deletePrivateKey(UPDATE_TAG);

    // Generate a key with initial label
    const keys = await RSAKeychain.generate(UPDATE_TAG, false, 'Initial Label');
    console.log('Generated key with initial label');

    // Update the label
    const updateSuccess = await RSAKeychain.updatePrivateKey(
      UPDATE_TAG,
      'Updated Label',
    );
    console.log('Update label success:', updateSuccess);

    // Verify the label was updated by checking all keys
    const allKeys = await RSAKeychain.getAllKeys();
    const updatedKey = allKeys.find(key => key.tag === UPDATE_TAG);
    console.log('Updated key info:', updatedKey);

    const deleteSuccess = await RSAKeychain.deletePrivateKey(UPDATE_TAG);
    console.log('Delete success:', deleteSuccess);

    // On iOS, updateSuccess should be true. On Android, it will be false due to platform limitations
    return deleteSuccess;
  } catch (e) {
    console.log('updatePrivateKeyDemo failed:', e);
    return false;
  }
};

export default updatePrivateKeyDemo;
