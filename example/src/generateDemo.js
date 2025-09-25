import { RSA } from 'react-native-rsa-native';

const generateDemo = async () => {
  try {
    console.log('generateDemo');
    const keys = await RSA.generate();
    console.log('private:', keys.private);
    console.log('public:', keys.public);
    const encodedMessage = await RSA.encrypt('1234', keys.public);
    console.log('encoded message:', encodedMessage);
    const message = await RSA.decrypt(encodedMessage, keys.private);
    console.log('decoded message:', message);
    return message === '1234';
  } catch (e) {
    console.log('generateDemo failed:', e);
    return false;
  }
};

export default generateDemo;
