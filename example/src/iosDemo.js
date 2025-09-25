import { RSA } from 'react-native-rsa-native';

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

export default iosDemo;
