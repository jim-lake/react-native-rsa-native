import { RSA } from 'react-native-rsa-native';

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

export default androidDemo;
