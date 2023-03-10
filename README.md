<div align=center><h2>x509</h2></div>

<div align=center><h3>Две реализации создания ключа и сертификата х509</h3></div>

### micro509
Создана для использования с https клиентом.\
Небольшой размер достигнут за счёт отсутствия информации в issuer и subject.

Принимает два параметра:\
key: <b>int</b> длинна модуля ключа (1024, 2048, 4096)\
sign: <b>int</b> длинна подписи sha (1, 256, 384, 512)

На выходе: <b>object</b>\
key:  <b>string</b> приватный ключ в pem формате\
cert: <b>string</b> сертификат в pem формате

### full509
Более полная реализация поддерживающая версию 3, генерацию полей в issuer и subject, ограниченную реализацию extensions.

<br>
<blockquote style="background:#555302; color: white">
  <br>
    <p>Ограничения</p>
    1. В extensions доступны только altName<br>
    2. В altName реализованны: dNSName, iPAddress, rfc822Name, uniformResourceIdentifier<br>
    3. Подпись: sha 1, 256, 384, 512
  <br><br>
</blockquote>
<br>

Возможны три сценария использования:

1. Генерация цепочки сертификатов (root, srv)
2. Генерация одного сертификата (srv) и указание в параметрах пути к приватному ключу и сертификату (root), который подпишет srv сертификат
3. Генерация одного сертификата

Параметры: <b>object</b>\
Обязательными являються: type, sign, curve (для ecdsa), lenght (для rsa)
###### Общий пример
```js
{
  srv: {
    type: 'ecdsa',
    curve: 'sect239k1',
    sign: 'SHA256',
    serial: 123,
    validity: {
      notBefore: '2020-12-12',
      notAfter: '2033-12-12',
    },
    subject: {
      countryName: 'EA',
      stateOrProvinceName: 'EARTH',
      organizationName: 'DO_NOT_TRUST', 
      commonName: '*.example.ru',
    },
    altName: [
      ['dNSName', 'www.example.ru'],
      ['iPAddress', '127.0.0.1'],
      ['iPAddress', '1234:5678:9000:abcd:9876:5432:10ab:cdef'],
    ],
    altName: {dNSName: 'www.example.ru'},
  },
  root: {
    type: 'rsa',
    lenght: 2048,
    sign: 256,
    serial: '321',
    validity: {
      notBefore: '2000-01-01',
      notAfter: '3000-12-31',
    },
    issuer: {
      countryName: 'EA',
      stateOrProvinceName: 'EARTH',
      organizationName: 'DO_NOT_TRUST', 
      commonName: 'DO_NOT_TRUST_LOCAL_ROOT',
    },
    subject: {
      countryName: 'EA',
      stateOrProvinceName: 'EARTH',
      organizationName: 'DO_NOT_TRUST', 
      commonName: 'DO_NOT_TRUST_LOCAL_ROOT',
    },
  },
  root: {
    key: './RootCA.key',
    cert: './RootCA.pem',
  },
  path: './new_cert',
  prefix: Date.now(),
}
```
###### Без цепочки
```js
{
  type: 'ecdsa',
  curve: 'sect239k1',
  sign: 'SHA256',
  serial: 123,
  validity: {
    notBefore: '2020-12-12',
    notAfter: '2033-12-12',
  },
  issuer: {
    countryName: 'EA',
    stateOrProvinceName: 'EARTH',
    organizationName: 'DO_NOT_TRUST', 
    commonName: 'DO_NOT_TRUST_LOCAL_ROOT',
  },
  subject: {
    countryName: 'EA',
    stateOrProvinceName: 'EARTH',
    organizationName: 'DO_NOT_TRUST', 
    commonName: '*.example.ru',
  },
  altName: [
    ['dNSName', 'www.example.ru'],
    ['iPAddress', '127.0.0.1'],
    ['iPAddress', '1234:5678:9000:abcd:9876:5432:10ab:cdef'],
  ],
  path: './new_cert',
  prefix: Date.now(),
}
```

На выходе: <b>object</b>\
для цепочки:
```js
{
  root: {
    key: string pem format
    cert: string pem format
  },
  srv: {
    key: string pem format
    cert: string pem format
  },
}
```
для внешнего root:
```js
{
  srv: {
    key: string pem format
    cert: string pem format
  },
}
```
для одиночного:
```js
{
  key: string pem format
  cert: string pem format
}
```

Фаилы:
crt в формате der (бинарный), остальные в pem (текстовый)\
для цепочки:
```
PREFIX_root_certificate.crt
PREFIX_root_certificate.pem
PREFIX_root_private.pem
PREFIX_srv_certificate.crt
PREFIX_srv_certificate.pem
PREFIX_srv_private.pem
```
для внешнего root:
```
PREFIX_srv_certificate.crt
PREFIX_srv_certificate.pem
PREFIX_srv_private.pem
```
для одиночного:
```
PREFIX_certificate.crt
PREFIX_certificate.pem
PREFIX_private.pem
```
