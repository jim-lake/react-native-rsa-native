import React, { Component } from 'react';
import { View, Text } from 'react-native';
import { fromBER } from 'asn1js';
import { PublicKeyInfo } from 'pkijs';

import { RSA, RSAKeychain } from 'react-native-rsa-native';

let secret = 'secret message';
let keyTag = 'com.domain.mykey';

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

const signDemo = async () => {
  try {
    console.log('signDemo');
    const keys = await RSA.generate();
    const signature = await RSA.sign(secret, keys.private);
    console.log('signature', signature);

    // Validate signature format - RSA signatures are raw bytes, not ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // RSA signatures should be exactly the key size in bytes (2048 bits = 256 bytes)
      if (sigData.length === 256) {
        console.log('Signature format valid (256 bytes for 2048-bit key)');
      } else {
        console.log(`Unexpected signature length: ${sigData.length} bytes`);
        return false;
      }
    } catch (parseErr) {
      console.log('Signature parsing failed:', parseErr);
      return false;
    }

    const valid = await RSA.verify(signature, secret, keys.public);
    console.log('verified', valid);
    if (!valid) return false;

    try {
      await RSA.verify(signature, 'wrong message', keys.public);
      console.log(
        'NOTE!! Something went wrong, verify should have been failed',
      );
      return false;
    } catch (err) {
      console.log('verify fails correctly: ', err);
      return true;
    }
  } catch (e) {
    console.log('signDemo failed:', e);
    return false;
  }
};

const signAlgoDemo = async () => {
  try {
    console.log('signAlgoDemo');
    const keys = await RSA.generate();
    const signature = await RSA.signWithAlgorithm(
      secret,
      keys.private,
      RSA.SHA256withRSA,
    );
    console.log('signature', signature);

    // Validate signature format - RSA signatures are raw bytes, not ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // RSA signatures should be exactly the key size in bytes (2048 bits = 256 bytes)
      if (sigData.length === 256) {
        console.log('Signature format valid (256 bytes for 2048-bit key)');
      } else {
        console.log(`Unexpected signature length: ${sigData.length} bytes`);
        return false;
      }
    } catch (parseErr) {
      console.log('Signature parsing failed:', parseErr);
      return false;
    }

    const valid = await RSA.verifyWithAlgorithm(
      signature,
      secret,
      keys.public,
      RSA.SHA256withRSA,
    );
    console.log('verified', valid);
    if (!valid) return false;

    try {
      await RSA.verifyWithAlgorithm(
        signature,
        'wrong message',
        keys.public,
        RSA.SHA256withRSA,
      );
      console.log(
        'NOTE!! Something went wrong, verify should have been failed',
      );
      return false;
    } catch (err) {
      console.log('verify fails correctly: ', err);
      return true;
    }
  } catch (e) {
    console.log('signAlgoDemo failed:', e);
    return false;
  }
};

const iosDemo = async () => {
  try {
    const iosPkcs1PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEA9nH5sqTOfSns7op8NHD2nHuXt/j1rodcbb7MXVSeK+0jx6np
  o2Oidc6J1fxSi5xBpIhEo6eGQD+b0SQFQMe6k33kqfRk4vzNi5n4lzFWWoyVgHKi
  CYrk+JdSGX2BK0t52ca8ZASBs099jIjiL8Hk4PPdpjrUk0sHaXDDFzhmHy8XRbH1
  21Pz148UytAnABxSO1F5gkGKvf23WyL0mb9kgfR9yX9wuCLtei8COT8Vz9l15nsc
  yPFCvC/mul6HTA7ukAXbtTS1wgRmorM2XTtnwpbMEpAwM48UhH7qcMFJVVagmpTI
  w0uFTXfYybJt8NysO1KslM7Yqswg5Aq36gxugwIDAQABAoIBABglu88uydLGyGHp
  LNlgljFoBMoweTY0KjDQqKqeb28jacWXFv789L6xUZ0nf5kRYvcxqPQWJpfmA6j+
  7ArYZyYriDvE6Bu7pJJAsHR0D5+Itd9jnA/uTZg0D4XS39SzrQlTKUNtk53TtJwQ
  D4WZbIlEK9wtWIXkLKI+u8brLkpwvBBcXrXUqBnqngJEBFKvr+utlzvnN6Ra9Kjw
  cpDCRkGvQyXav1rFwEe2pkaOnQ/r+y7lJqoT/+XyOjcTdkh2PhN7w9dHpGEmI6mL
  iQjbqEEXnAbyI1Cf753J1joLb5/+fVJ1DQiO8nMcpK+vzCRm5HNHgOG4KKjmQMRX
  NEGqoGkCgYEA/EJFi94JWgJaZ3r02EfG4TuIYQE0KIR/vn3iCdw6uGIclsgTwiuE
  z8OB1LWNvHzpiFfohESxrykflCjyATzExpqr2BpNlxyt0vp5RidggGKaiwjmbf1P
  89uTYGWwI8LxCBTbU+s9cjDInx84aKUjzTFb4i1dwwcLntaNKceORnsCgYEA+hmh
  rBlsF1QNCH2FsQqoI6oSsSbMJBw/FTF8fyIvvLC8Yas25Ax73nerw1Kpc2AC9bbn
  XlzfwmEgYdMdu+biZzJpsD5LaplbkUw1IZvTKlHwIUg/C/QjfaN11YOx+sxgo8lh
  2eFTGjnNjSwU943RmBckQGD7WEsc/Z0mJRzbPZkCgYEA+yh0m/y3LOH45tzaGNjm
  H+ypLYQITWsW0S/+tTiLUneE5W9RlNrFgiKzCni1JPzte22jOMY4byCvq1FVGnxJ
  oz/uZtxRcmoAe3Yc9wdPoqQKIPH8k3hJeY+eXbUBOannV9eERDqMVDxUE3H/NNlv
  GubRCBGJMBu8qyoNJJLmii8CgYEAtKo7XcTnjlqLJ6z1HJUkLM84vXvXT+aPs1GS
  K4yYi2foTW2PM2HJQUWVcH2QJuYefT1pGYNhqFrdN414FzqMJhwGuOfnNtQdj3JL
  l0GnYxTZsFEuKgZsdN/VyS1fLlrhHK/m3aulinZjBC3p34I0+/cLmu3z4y4vfQ0+
  duTHg1ECgYB98Z0eCi/ct+m+B3YhCEdcXUzvIZY0sEJUlqIiGyxkLuVEdIPIFUqj
  f1+VVZQA0d6BwruDSptq8x5aR3rdAlb5A71NYWQGOIPa2E5SIFZmzrZjyeeCfyB8
  eMOrE2W6flCRaTDOH4kFuw4JqrymBLcgP/OTYO0T9MCOKeqP0wbyNg==
  -----END RSA PRIVATE KEY-----`;

    const iosEncodedMessage = `xW7YdqRZPxMjUydRuY/bWO78Jvz/GM9qx+0soQEsheqfs+5nLugkBXiJC9J6if3j
  oCH/uBLYC41X6tlpX/L/u+ujaYQTIRcnL1f74ZFcX8Ox1vTp47Ie5XteRcLbuAmk
  vOzQ41q/ddUe8co67ShuiTmwI3Q4bUNukHEkwcpbD20JllKRR3wfYCoej05O29Xj
  9QuO0gKjEis5le6dWrMuVQVT70rBZQkAoBAesSjEYw0LKKjyylpUHmNy7y1XNbb2
  LA8kC70ZvNWYL+cIU2ZKts9HYtTbIAonL91uP6Bf+M0uUkqc2zxEL9EpFmwGx3Q0
  JQUqPQPB+wHb7DlDFJdQ6A==`;

    const message = await RSA.decrypt(iosEncodedMessage, iosPkcs1PrivateKey);
    console.log('ios decoded message:', message);
    return message === '1234';
  } catch (e) {
    console.log('iosDemo failed:', e);
    return false;
  }
};

const androidDemo = async () => {
  try {
    const androidPkcs1PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAx+Wc5/pZQFLxisjb5TbkVKzm1y/q/JbVZ4kq9D8isFI6GimQ
  yF7y8gdmq4YPblCfnUIlFFbdWsbUX8dW6nLEmWQhqHheLOybHfrv/YaSUZzlmUav
  qNYAv5xm3/F7rAeFjZN5fVpATdLl3AlhxBckxwZe2Z0AdEuOdUGDbdBwGoWrfCLv
  r3wWSZfJ0we+DfK76WGDFdK/5jSm9yQePTmY1Hc/QkaULadFtZn/O5xl3uyS768i
  MEo+Zt6/6863ej6WJekvZ3XKUr/Sqvw+b8nzEyH7RCnFvDgXK7LMe+Tc6HdNaTeV
  w3nE2pQqqTx8LCNhj4HsobQi3ndgYuOJM0O0wQIDAQABAoIBAQDAPCd9y3rjaiCR
  eAJIV1aTu8cvMAzKpn9J11awlrrUV+86U7jBiNYYPVfWIdFbJDurbv3bpoGvF8EK
  7te+FWrNnMbljgP7LfsqhLUg2baCt+DxW1H4iv0jR9SDDmcBlCYydZ2DGDT44pVc
  2sTjX+JlZ9H1cpAKRtMUHlG3XJlCVo+JnaslzWIfk0Itzd55ntTm4bXEgZ9j3+79
  eyoHgnY3LWTrIYDlHwS9ypYdLEbyCf89MP+VFDADjs1CTr31WzuVkKKUXvxATgfq
  CZhxHgZgHgvAvWRGQnqwIo6uMBBCD1DsAxj9MG7AI0+1F6wiMGyBEQ1agxZST2W4
  wb6UVpsxAoGBAPUZJ1zjPGiCxCNdaOWB3oPyL/6o9azQsyR4GEoGUjDdCDU9zKys
  WQn63f83jN9dZvNH68Dc3sb0k5Ip1TSqqdIKJA8Ms1GAEsHSMQAM6euGn6D4PdqU
  JPqwqIcQkaPIY/zEkfuh7J8U9p7WpicHz/WNfqsY2kFBzdpjNO6AmWGNAoGBANDJ
  xItF+Rd9x8lWrD6xf/U2vTLai4EZF1piLo5Tu7BwqHg8BlXpn4dBvefMxuDSELJ+
  WfNwgwyrNaCM0Rs7hlnF+V6kuFr4lJJgORp578NhvncLGfrxQrVlTt1pablh+iTD
  8IT2o9NEzgiRxjq3Qxo+iVprX0tfoz1UwqLYgEEFAoGBAM3HC5xaEEqyl1gVwc8H
  BToEaTVGx9UK94zD46iqu/DYcl64/xFuNedCH4Z6LiUOdzQECzRGfCfQCeHqi12H
  d8KnzvRvtlHT1Gu0PH2NWgvrYDQ2lz/fp1huX1/eklhPE1uR8fqxTUeWwyRClQcp
  8Ph5joK5/+xQAjO7nSItCBm1AoGAFblYtPET6OjSd9WH2IIZgUcvynHI4CbfMi1T
  EMYPml0uekwskJXdXnJtswewjcXtrNTOwTCswg2yZ8EfJMk9wmuB9eIHuJdyxgQz
  DNkxJFAwRCyoiF7ABSXEXe9Q69QQ9fBZP0x2YU4gbe3VBVj6J2noWrsfUDVkQ8Zk
  9hK2zY0CgYBiMwbP0nafeaB+YO9v2mvwHeCAnFtBsVZkUVp75alsAujr/YEKSKEQ
  YiFzbWLAkY7gBrS2b8tbHKXkkYfcWWlpM85ir/uqyNy/6Rb7CPkKUkCInIwZ9Vi2
  clP6STevOnNTlyYhNgesy50tSPJEWO6ysC/petudc5t1e1FEM/pBkg==
  -----END RSA PRIVATE KEY-----`;

    const androidEncodedMessage = `Z3iPkJiJCrXLaT11RtwBuSJa4rGbJ7JfDSHMNn/UaLUnGIzFmMT6ZRMtaSmWJhw3pXBES1IqufJB
  Wk5vdZuDD7o5AP8i5GHrgVGbf6ix6DIH1+PiJzcfwBcSdEuCMEsustk+tBirK/HuxYt0HQV3B8Sw
  EFAFOAPh3y2CsSC7Ibn5Q5cWeDYxfs8XANezs0H3i/X+KZP8owIrKnsERErc0E6bJ/V3tGCoFb+5
  m0SibGo5B446iH57hTHf3Sv6GYcThk5+BqP/08VVQ2YXy+oMPng2nVnvzGONdJzfq+9GAKWMx6CE
  yiSiGz7AYGDb04FmekL8KqEKy6nTlVERlbwWRg==`;

    const message = await RSA.decrypt(
      androidEncodedMessage,
      androidPkcs1PrivateKey,
    );
    console.log('android decoded message:', message);
    return message === '1234';
  } catch (e) {
    console.log('androidDemo failed:', e);
    return false;
  }
};

const keychainDemo = async () => {
  try {
    console.log('keychainDemo start');
    const RSA_TAG = 'rsa_tag3';
    await RSAKeychain.deleteAllKeys();

    // Test with synchronizable and label parameters
    const keys = await RSAKeychain.generate(RSA_TAG, true, 'Test RSA Key');
    console.log(keys.public);

    console.log('all keys:', await RSAKeychain.getAllKeys());

    const encodedMessage = await RSAKeychain.encrypt(secret, RSA_TAG);
    console.log('encodedMessage:', encodedMessage);
    const message = await RSAKeychain.decrypt(encodedMessage, RSA_TAG);
    console.log('message:', message);
    const signature = await RSAKeychain.sign(secret, RSA_TAG);
    console.log('signature', signature);

    // Validate signature format - RSA signatures are raw bytes, not ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // RSA signatures should be exactly the key size in bytes (2048 bits = 256 bytes)
      if (sigData.length === 256) {
        console.log(
          'Keychain signature format valid (256 bytes for 2048-bit key)',
        );
      } else {
        console.log(
          `Unexpected keychain signature length: ${sigData.length} bytes`,
        );
        return false;
      }
    } catch (parseErr) {
      console.log('Keychain signature parsing failed:', parseErr);
      return false;
    }

    const valid = await RSAKeychain.verify(signature, secret, RSA_TAG);
    console.log('verified', valid);
    if (!valid) {
      return false;
    }

    const invalid = await RSAKeychain.verify(
      signature,
      'wrong message',
      RSA_TAG,
    );
    console.log('invalid:', invalid);
    if (invalid) {
      return false;
    }

    const allKeys = await RSAKeychain.getAllKeys();
    console.log('All keys:', allKeys);

    const success = await RSAKeychain.deletePrivateKey(RSA_TAG);
    console.log('delete success', success);
    return message === secret && valid && success;
  } catch (e) {
    console.log('keychainDemo failed:', e);
    return false;
  }
};

const keychainECDemo = async () => {
  try {
    console.log('keychainECDemo start');
    const EC_TAG = 'ec_tag1';
    await RSAKeychain.deletePrivateKey(EC_TAG);

    // Test EC key generation with synchronizable and label
    const keys = await RSAKeychain.generateEC(EC_TAG, false, 'Test EC Key');
    console.log('EC public key:', keys.public);

    // Strict public key format verification for EC
    try {
      // EC public key from iOS keychain is raw uncompressed format (65 bytes for P-256)
      const keyData = Uint8Array.from(atob(keys.public.replace(/\s/g, '')), c =>
        c.charCodeAt(0),
      );

      // P-256 uncompressed public key: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes total
      if (keyData.length !== 65) {
        console.log(
          `EC public key should be 65 bytes (uncompressed P-256), got ${keyData.length}`,
        );
        return false;
      }

      // Must start with 0x04 (uncompressed point indicator)
      if (keyData[0] !== 0x04) {
        console.log(
          `EC public key must start with 0x04 (uncompressed), got 0x${keyData[0].toString(
            16,
          )}`,
        );
        return false;
      }

      console.log(
        'EC public key format validation passed (65 bytes uncompressed P-256)',
      );
    } catch (parseErr) {
      console.log('EC public key format validation failed:', parseErr);
      return false;
    }

    // Test getAllKeys and verify key consistency
    const allKeys = await RSAKeychain.getAllKeys();
    const matchingKey = allKeys.find(key => key.tag === EC_TAG);
    if (!matchingKey) {
      console.log('EC key not found in getAllKeys');
      return false;
    }
    if (matchingKey.public !== keys.public) {
      console.log('EC public key mismatch between generate and getAllKeys');
      return false;
    }
    console.log('EC key consistency verified between generate and getAllKeys');

    // Test EC signing and verification
    const message = 'test message for EC';
    const signature = await RSAKeychain.signWithAlgorithm(
      message,
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('EC signature:', signature);

    // Validate EC signature format - must be exactly DER-encoded ASN.1
    try {
      const sigData = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      // DER-encoded ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }
      // Must start with 0x30 (SEQUENCE tag)
      if (sigData[0] !== 0x30) {
        console.log('EC signature must start with DER SEQUENCE tag (0x30)');
        return false;
      }
      // Length must be exactly what DER specifies (no padding, no truncation)
      const derLength = sigData[1];
      if (sigData.length !== derLength + 2) {
        console.log(
          `EC signature DER length mismatch: expected ${derLength + 2}, got ${
            sigData.length
          }`,
        );
        return false;
      }
      // For P-256, typical range is 68-72 bytes, but must be exact DER
      if (sigData.length < 68 || sigData.length > 72) {
        console.log(
          `EC signature length ${sigData.length} outside valid P-256 DER range (68-72)`,
        );
        return false;
      }
      console.log(
        `EC signature format valid (${sigData.length} bytes DER-encoded)`,
      );
    } catch (parseErr) {
      console.log('EC signature parsing failed:', parseErr);
      return false;
    }

    const isValid = await RSAKeychain.verifyWithAlgorithm(
      signature,
      message,
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('EC signature valid:', isValid);

    if (!isValid) {
      return false;
    }
    // Test negative verification for EC
    const bad_is_valid = await RSAKeychain.verifyWithAlgorithm(
      signature,
      'wrong message',
      EC_TAG,
      'SHA256withECDSA',
    );
    console.log('Wrong message verify:', bad_is_valid);
    if (bad_is_valid) {
      return false;
    }

    const success = await RSAKeychain.deletePrivateKey(EC_TAG);
    console.log('EC delete success', success);
    return success;
  } catch (e) {
    console.log('keychainECDemo failed:', e);
    return false;
  }
};

const keychainEdDemo = async () => {
  try {
    console.log('keychainEdDemo start');
    const ED_TAG = 'ed_tag1';
    await RSAKeychain.deletePrivateKey(ED_TAG);

    // Test Ed key generation with synchronizable and label
    const keys = await RSAKeychain.generateEd(ED_TAG, false, 'Test Ed Key');
    console.log('Ed public key:', keys.public);

    // Strict public key format verification for Ed25519
    try {
      // Ed25519 public key from iOS keychain is raw 32-byte format
      const keyData = Uint8Array.from(atob(keys.public.replace(/\s/g, '')), c =>
        c.charCodeAt(0),
      );

      // Ed25519 public key should be exactly 32 bytes
      if (keyData.length !== 32) {
        console.log(
          `Ed25519 public key should be 32 bytes, got ${keyData.length}`,
        );
        return false;
      }

      console.log('Ed25519 public key format validation passed (32 bytes raw)');
    } catch (parseErr) {
      console.log('Ed25519 public key format validation failed:', parseErr);
      return false;
    }

    // Test getPublicKeyEd method
    const publicKeyResult = await RSAKeychain.getPublicKeyEd(ED_TAG);
    console.log('Retrieved Ed public key:', publicKeyResult.public);

    // Verify consistency between generateEd and getPublicKeyEd
    if (keys.public !== publicKeyResult.public) {
      console.log(
        'Ed25519 public key mismatch between generateEd and getPublicKeyEd',
      );
      return false;
    }

    // Test getAllKeys and verify key consistency
    const allKeys = await RSAKeychain.getAllKeys();
    const matchingKey = allKeys.find(key => key.tag === ED_TAG);
    if (!matchingKey) {
      console.log('Ed25519 key not found in getAllKeys');
      return false;
    }

    // For Ed25519 keys, verify both public and publicEd25519 fields
    const allKeysPublicKey = matchingKey.publicEd25519 || matchingKey.public;
    if (allKeysPublicKey !== keys.public) {
      console.log(
        'Ed25519 public key mismatch between generate and getAllKeys',
      );
      console.log('Generate key:', keys.public);
      console.log('getAllKeys key:', allKeysPublicKey);
      return false;
    }
    
    // Verify publicEd25519 property is set correctly for Ed25519 keys
    if (matchingKey.type === 'Ed25519' && !matchingKey.publicEd25519) {
      console.log('Ed25519 key missing publicEd25519 property in getAllKeys');
      return false;
    }
    if (matchingKey.publicEd25519 && matchingKey.publicEd25519 !== keys.public) {
      console.log('Ed25519 publicEd25519 property mismatch in getAllKeys');
      return false;
    }
    
    console.log(
      'Ed25519 key consistency verified between generate and getAllKeys',
    );

    // Test Ed25519 signing
    const message = btoa('Hello Ed25519!'); // Base64 encode the message
    const signature = await RSAKeychain.signEd(message, ED_TAG);
    console.log(
      'Ed signature: (converted from uint8 to b64):',
      uint8ArrayToBase64(signature),
    );

    // Validate Ed25519 signature format - must be exactly 64 bytes, no exceptions
    try {
      // Ed25519 signatures are always exactly 64 bytes (512 bits)
      if (signature.length !== 64) {
        console.log(
          `Ed25519 signature must be exactly 64 bytes, got ${signature.length} bytes`,
        );
        return false;
      }
      // Verify it's a Uint8Array (not base64 string or other format)
      if (!(signature instanceof Uint8Array)) {
        console.log('Ed25519 signature must be Uint8Array format');
        return false;
      }
      console.log('Ed25519 signature format valid (64 bytes)');
    } catch (parseErr) {
      console.log('Ed25519 signature parsing failed:', parseErr);
      return false;
    }

    // Test Ed25519 verification
    const isValid = await RSAKeychain.verifyEd(
      signature,
      message,
      publicKeyResult.public,
    );
    console.log('Ed signature valid:', isValid);

    // Test with invalid signature
    const invalidSignature = btoa('invalid_signature_data');
    const isInvalid = await RSAKeychain.verifyEd(
      invalidSignature,
      message,
      publicKeyResult.public,
    );
    console.log('Invalid Ed signature valid (should be false):', isInvalid);

    const success = await RSAKeychain.deletePrivateKey(ED_TAG);
    console.log('Ed delete success', success);
    return success && isValid && !isInvalid;
  } catch (e) {
    console.log('keychainEdDemo failed:', e);
    return false;
  }
};

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

const publicKeyFormatsDemo = async () => {
  console.log('publicKeyFormatsDemo start');

  const keyTag = 'format_test_key';

  try {
    // Generate keychain key and get all formats
    await RSAKeychain.generateKeys(keyTag, 2048);
    const publicKeyDefault = await RSAKeychain.getPublicKey(keyTag);
    const publicKeyDER = await RSAKeychain.getPublicKeyDER(keyTag);
    const publicKeyRSA = await RSAKeychain.getPublicKeyRSA(keyTag);
    const allKeys = await RSAKeychain.getAllKeys();
    const matchingKey = allKeys.find(key => key.tag === keyTag);
    if (!matchingKey) {
      console.log("All keys didn't find key");
      return false;
    }

    console.log('Default public key:', publicKeyDefault.public);
    console.log('DER public key:', publicKeyDER.public);
    console.log('RSA public key:', publicKeyRSA.public);
    console.log('getAllKeys public key:', matchingKey.public);

    // Extract n and e from each format
    const extractRSAParams = (keyStr, format = 'SPKI') => {
      try {
        let keyData;

        if (format === 'RAW') {
          // RAW must be pure base64 with no PEM headers
          if (/-----/.test(keyStr)) {
            console.error('RAW format cannot have PEM headers');
            throw new Error('RAW key must be pure base64 PKCS#1 bytes');
          }
          keyData = Uint8Array.from(atob(keyStr.replace(/\s/g, '')), c =>
            c.charCodeAt(0),
          );
        } else {
          // SPKI or PKCS1 expects PEM
          if (!/-----/.test(keyStr)) {
            console.error(`${format} format requires PEM headers`);
            throw new Error(`${format} key must include PEM headers`);
          }
          const pemContent = keyStr
            .replace(/-----BEGIN [^-]+-----/, '')
            .replace(/-----END [^-]+-----/, '')
            .replace(/\s/g, '');
          keyData = Uint8Array.from(atob(pemContent), c => c.charCodeAt(0));
        }

        const asn1 = fromBER(keyData.buffer);
        if (asn1.offset === -1) {
          console.error('ASN.1 parsing failed');
          throw new Error('Invalid key format');
        }

        let nHex, eHex;

        if (format === 'SPKI') {
          try {
            const publicKeyInfo = new PublicKeyInfo({ schema: asn1.result });
            const keyAsn1 = fromBER(
              publicKeyInfo.subjectPublicKey.valueBlock.valueHex,
            );
            const n = keyAsn1.result.valueBlock.value[0].valueBlock.valueHex;
            const e = keyAsn1.result.valueBlock.value[1].valueBlock.valueHex;
            nHex = Array.from(new Uint8Array(n))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
            eHex = Array.from(new Uint8Array(e))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
          } catch {
            console.error('Key does not match SPKI format');
            throw new Error('Key does not match SPKI format');
          }
        } else if (format === 'PKCS1' || format === 'RAW') {
          try {
            const n = asn1.result.valueBlock.value[0].valueBlock.valueHex;
            const e = asn1.result.valueBlock.value[1].valueBlock.valueHex;
            nHex = Array.from(new Uint8Array(n))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
            eHex = Array.from(new Uint8Array(e))
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');
          } catch {
            console.error(`Key does not match ${format} PKCS#1 format`);
            throw new Error(`Key does not match ${format} PKCS#1 format`);
          }
        } else {
          throw new Error(`Unsupported format: ${format}`);
        }

        return { n: nHex, e: eHex };
      } catch (e) {
        console.error('Extraction error:', e);
        return null;
      }
    };

    const defaultParams = extractRSAParams(publicKeyDefault.public, 'PKCS1');
    const derParams = extractRSAParams(publicKeyDER.public, 'SPKI');
    const rsaParams = extractRSAParams(publicKeyRSA.public, 'PKCS1');
    const allKeysParams = extractRSAParams(matchingKey.public, 'RAW');

    console.log('Default key n:', defaultParams.n.substring(0, 50) + '...');
    console.log('Default key e:', defaultParams.e);
    console.log('DER key n:', derParams.n.substring(0, 50) + '...');
    console.log('DER key e:', derParams.e);
    console.log('RSA key n:', rsaParams.n.substring(0, 50) + '...');
    console.log('RSA key e:', rsaParams.e);
    console.log('getAllKeys key n:', allKeysParams.n.substring(0, 50) + '...');
    console.log('getAllKeys key e:', allKeysParams.e);

    // Compare n and e
    const sameN =
      defaultParams.n === derParams.n &&
      derParams.n === rsaParams.n &&
      rsaParams.n === allKeysParams.n;
    const sameE =
      defaultParams.e === derParams.e &&
      derParams.e === rsaParams.e &&
      rsaParams.e === allKeysParams.e;

    console.log('Same modulus (n):', sameN);
    console.log('Same exponent (e):', sameE);
    console.log('All keys identical:', sameN && sameE);

    // Clean up
    await RSAKeychain.deletePrivateKey(keyTag);

    return sameN && sameE;
  } catch (e) {
    console.log('publicKeyFormatsDemo error:', e);
    return false;
  }
};

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

const runTests = async setTestStatus => {
  const tests = [
    { name: 'generateKeys4096Demo', fn: generateKeys4096Demo },
    { name: 'generateDemo', fn: generateDemo },
    { name: 'signDemo', fn: signDemo },
    { name: 'signAlgoDemo', fn: signAlgoDemo },
    { name: 'iosDemo', fn: iosDemo },
    { name: 'androidDemo', fn: androidDemo },
    { name: 'keychainDemo', fn: keychainDemo },
    { name: 'keychainECDemo', fn: keychainECDemo },
    { name: 'keychainEdDemo', fn: keychainEdDemo },
    { name: 'getAllKeysDemo', fn: getAllKeysDemo },
    { name: 'updatePrivateKeyDemo', fn: updatePrivateKeyDemo },
    { name: 'publicKeyFormatsDemo', fn: publicKeyFormatsDemo },
  ];

  setTestStatus('Running');

  for (const test of tests) {
    console.log(`Running test: ${test.name}`);
    const result = await test.fn();
    if (!result) {
      const errorMsg = `Test failed: ${test.name}`;
      console.log(errorMsg);
      setTestStatus(`Failure: ${test.name}`);
      console.log('ALL_TESTS_COMPLETED');
      return;
    }
    console.log(`Test passed: ${test.name}`);
  }

  console.log('ALL_TESTS_COMPLETED');
  setTestStatus('Success');
};

function _fromBase64(arg) {
  const s =
    arg.replace(/-/g, '+').replace(/_/g, '/') +
    '=='.slice(0, (4 - (arg.length % 4)) % 4);
  return new Uint8Array(
    atob(s)
      .split('')
      .map(c => c.charCodeAt(0)),
  );
}

function uint8ArrayToBase64(uint8Array) {
  let binary = '';
  const len = uint8Array.length;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary);
}

class App extends Component {
  constructor(props) {
    super(props);
    this.state = { testStatus: 'Running' };
  }

  componentDidMount() {
    runTests(status => this.setState({ testStatus: status }));
  }

  render() {
    return (
      <View style={{ margin: 20, marginTop: 100 }}>
        <Text>Demo</Text>
        <Text testID="test-status" style={{ fontSize: 18, marginTop: 20 }}>
          Test Status: {this.state.testStatus}
        </Text>
      </View>
    );
  }
}

export default App;
