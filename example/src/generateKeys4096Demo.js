import { RSA } from 'react-native-rsa-native';

const generateKeys4096Demo = async () => {
  try {
    console.log('generateKeys4096Demo');
    const keys = await RSA.generateKeys(4096);
    console.log('4096 private:', keys.private);
    console.log('4096 public:', keys.public);
    const encodedMessage = await RSA.encrypt('4096', keys.public);
    console.log('4096 encoded message:', encodedMessage);
    const message = await RSA.decrypt(encodedMessage, keys.private);
    console.log('4096 decoded message:', message);
    return message === '4096';
  } catch (e) {
    console.log('generateKeys4096Demo failed:', e);
    return false;
  }
};

export default generateKeys4096Demo;
