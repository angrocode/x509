import {generateKeyPairSync, createSign} from 'node:crypto'

export function micro509(key = 2048, sign = 256) {
  const {publicKey, privateKey} = generateKeyPairSync('rsa', {
    modulusLength: key,
    publicKeyEncoding:  {type: 'spki',  format: 'der'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
  })

  const algIdentKey = {1:'05', 256:'0B', 384:'0C', 512:'0D'}
  const algorithmIdentifier = `300D06092A864886F70D0101${algIdentKey[sign]}0500`

  const validity = ''
    + '30' + _toHex(34) // GeneralizedTime
    + '18' + _toHex(15) + _toHex('20000101000001Z')
    + '18' + _toHex(15) + _toHex('30001231235959Z')

  const tbsLenDec = 7 + (algorithmIdentifier.length / 2) + (validity.length / 2) + publicKey.byteLength
  const tbsLenHex = _toHex(tbsLenDec)
  const tbsCertificate = ''
    + '30' + (80 + (tbsLenHex.length / 2)) + tbsLenHex
    + '020101' + algorithmIdentifier + '3000'               
    + validity + '3000' + publicKey.toString('hex')

  const signature  = createSign(`SHA${sign}`).update(tbsCertificate, 'hex').end().sign(privateKey)
  const signLenHex = _toHex(1 + signature.byteLength)
  const signLenLen = signLenHex.length / 2

  const certLenDec = 0
    + (tbsCertificate.length / 2)
    + (algorithmIdentifier.length / 2)
    + (2 + signLenLen) + 1 + signature.byteLength
  const certLenHex  = _toHex(certLenDec)
  const certificate = ''
    + '30' + (80 + (certLenHex.length / 2)) + certLenHex
    + tbsCertificate + algorithmIdentifier
    + '03' + (80 + signLenLen) + signLenHex + '00' + signature.toString('hex')

  const b64Arr = Buffer.from(certificate, 'hex').toString('base64').match(/.{0,64}/g)
  return {
    key: privateKey,
    cert: '-----BEGIN CERTIFICATE-----\n' + b64Arr.join('\n') + '-----END CERTIFICATE-----\n'
  }

  function _toHex(data) {
    if (typeof data == 'string') {
      return Buffer.from(data, 'utf8').toString('hex')
    } else if (typeof data == 'number') {
      const hex = data.toString(16)
      return hex.padStart(hex.length + hex.length % 2, '0')
    }
  }
}
