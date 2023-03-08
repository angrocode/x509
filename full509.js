import { generateKeyPairSync, createPrivateKey, createPublicKey, createSign, createHash, X509Certificate } from 'node:crypto'
import { statSync, readFileSync, writeFileSync } from 'node:fs'


const tag = tags()
const oid = oids()
const gnType = gnTypes()

export function local509(params) {
  const savePath = params?.path && isObject(params.path) ? params.path : null
  if (savePath && !statSync(savePath).isDirectory()) 
    throw new Error(`the path '${savePath}' does not point to a directory`)

  const certСhain = ['root', 'srv']
  const certСhainСount = Object.keys(params).filter(k => certСhain.includes(k)).length
  if (certСhainСount > 0 && certСhainСount < 2) 
    throw new Error(`parameters must contain ${certСhain.toString()} or none of them`)
  const isСhain = certСhainСount == certСhain.length

  if (certСhainСount == 2) {
    if (!isObject(params.root)) 
      throw new Error(`root must be an object`)
    if (!isObject(params.srv)) 
      throw new Error(`srv must be an object`)
  }

  const extCertField = ['key', 'cert']
  const extCertСount = certСhainСount == 2 ? Object.keys(params.root).filter(k => extCertField.includes(k)).length : 0
  if (extCertСount > 0 && extCertСount < 2) 
    throw new Error(`root must contain ${extCertField.toString()} keys containing file paths`)
  const isExtRoot = extCertСount == extCertField.length

  if (isExtRoot) {
    if (!statSync(params.root.key ).isFile()) 
      throw new Error(`the path '${params.root.key}' does not point to the file`)
    if (!statSync(params.root.cert).isFile()) 
      throw new Error(`the path '${params.root.cert}' does not point to the file`)
    const cert =  new X509Certificate(readFileSync(params.root.cert))
    if (!cert.checkPrivateKey(getKeys(readFileSync(params.root.key)).privateObj)) 
      throw new Error(`a foreign key and a certificate are not a pair`)
  }

  const paramsArr = !isСhain 
    ? Object.entries({params})
    : Object.entries(params).filter(s => certСhain.includes(s[0]))

  const requiredKeys = ['type', 'sign']
  const validityKeys = ['notBefore', 'notAfter']
  const hashKeys     = ['1', '256', '384', '512']
  const subjectKeys  = Object.keys(oid.subject)
  const gnTypeKeys   = Object.keys(gnType)

  for (const [subj, param] of paramsArr) {
    if (subj == 'root' && isExtRoot) continue

    const keys = param?.type == 'ecdsa' 
      ? [...requiredKeys, 'curve'] 
      : [...requiredKeys, 'lenght']

    const altNameKeys = param?.altName 
      ? isObject(param.altName) ? Object.keys(param.altName) : param.altName.map(n => n[0])
      : []

    if (Object.keys(param).filter(k => keys.includes(k)).length != keys.length)
      throw new Error(`${subj}: required fields are missing, \nrequired: 555${keys.toString()}`)
    if (!hashKeys.includes(/\d+/.exec(param.sign)?.[0])) 
      throw new Error(`${subj}: only sha: ${hashKeys.toString()} is supported`)
    if (param?.issuer && Object.keys(param.issuer).filter(k => !subjectKeys.includes(k)).length)
      throw new Error(`${subj}: check the issuer fields, possible: ${subjectKeys.toString()}`)
    if (param?.subject && Object.keys(param.subject).filter(k => !subjectKeys.includes(k)).length)
      throw new Error(`${subj}: check the subject fields, possible: ${subjectKeys.toString()}`)
    if (altNameKeys.filter(k => !gnTypeKeys.includes(k)).length)
      throw new Error(`${subj}: unsupported altName type, possible: ${gnTypeKeys.toString()}`)
    if (param?.serial && !Number.isInteger(parseInt(param.serial, 10)))
      throw new Error(`${subj}: serial cannot be converted to int type`)
    if (param?.validity && !isObject(param?.validity))
      throw new Error(`${subj}: validity must be an object`)
    if (param?.validity && Object.keys(param.validity).filter(k => validityKeys.includes(k)).length != validityKeys.length)
      throw new Error(`${subj}: validity must contain: ${validityKeys.toString()}`)
    if (param?.validity && new Date(param?.validity[validityKeys[0]]) === 'Invalid Date')
      throw new Error(`${subj}: validity ${validityKeys[0]} cannot be converted to date type`)
    if (param?.validity && new Date(param?.validity[validityKeys[1]]) === 'Invalid Date')
      throw new Error(`${subj}: validity ${validityKeys[1]} cannot be converted to date type`)
  }

  const prefix = String(params?.prefix ?? '')

  if (isСhain && isExtRoot) {
    const root = external(params.root)
    const srv  = internal(params.srv)

    const srvPackage = certBuilder(params.srv.sign, srv, root)
    getCert(srvPackage.cert)

    if ('path' in params)
      saveFile(prefix, 'srv', srvPackage, params.path)

    return {srv: srvPackage}
  } else if (isСhain) {
    const root = internal(params.root)
    const srv  = internal(params.srv)

    const rootPackage = certBuilder(params.root.sign, root)
    getCert(rootPackage.cert)
    const srvPackage = certBuilder(params.srv.sign, srv, root)
    getCert(srvPackage.cert)

    if ('path' in params) {
      saveFile(prefix, 'root', rootPackage, params.path)
      saveFile(prefix, 'srv', srvPackage, params.path)
    }

    return {root: rootPackage, srv: srvPackage}
  } else {
    const srv  = internal(params)

    const srvPackage = certBuilder(params.sign, srv)
    getCert(srvPackage.cert)

    if ('path' in params)
      saveFile(prefix, '', srvPackage, params.path)

    return srvPackage
  }
}

function certBuilder(sign, srv, root) {
  const presenceRoot = !!root
  const extensions = presenceRoot ? {...srv.extensions, ...root.extensions} : srv.extensions

  const tbsCertificate = tripletBuilder(tag.SEQUENCE, [
    srv.version,
    srv.serialNumber,
    presenceRoot ? root.signature : srv.signature,
    presenceRoot ? root.subject : srv.issuer,
    srv.validity,
    srv.subject,
    srv.subjectPublicKeyInfo,
    tripletBuilder(context(3, true), tripletBuilder(tag.SEQUENCE, Object.values(extensions)))
  ])

  const signNum = /\d+/.exec(sign)[0]
  const signature = createSign(`SHA${signNum}`)
    .update(tbsCertificate, 'hex')
    .end()
    .sign(presenceRoot ? root.privateObj : srv.privateObj)

  const certificate = tripletBuilder(tag.SEQUENCE, [
    tbsCertificate,
    presenceRoot ? root.signature : srv.signature,
    tripletBuilder(tag.BITSTRING, '00' + signature.toString('hex'))
  ])

  return {
    key:  srv.privateObj.export({type: 'pkcs8', format: 'pem'}),
    cert: printCert(certificate),
  }
}

function internal(params) {
  const signNum = /\d+/.exec(params.sign)[0]

  const issuerParams = Object.entries(params?.issuer ?? {}).map(([t, v]) => {
    return relativeDistinguishedName(oid['subject'][t], v)
  })

  const subjectParams = Object.entries(params?.subject ?? {}).map(([t, v]) => {
    return relativeDistinguishedName(oid['subject'][t], v)
  })

  const altNameParams = params?.altName 
    ? isObject(params.altName) ? Object.entries(params.altName) : params.altName
    : null
  
  const keyType = params.type == 'ecdsa' ? 'ec' : 'rsa'
  const keyParams = params.type == 'ecdsa' 
    ? {namedCurve: params.curve} 
    : {modulusLength: parseInt(params.lenght, 10)}

  const {publicKey, privateKey} = generateKeyPairSync(keyType, {
    ...keyParams,
    publicKeyEncoding:  {type: 'spki',  format: 'der'},
    privateKeyEncoding: {type: 'pkcs8', format: 'der'},
  })

  const hashPubKey = getHashPubKey(publicKey)

  const extensions = {
    subjectKeyIdentifier: subjectKeyIdentifier(hashPubKey),
    authorityKeyIdentifier: authorityKeyIdentifier(hashPubKey),
    basicConstraints: basicConstraints(),
  }
  if (altNameParams) extensions.subjectAltName = subjectAltName(altNameParams)

  return {
    ...getKeys(privateKey),
    version: version(2),
    serialNumber: serialNumber(parseInt(params?.serial, 10)),
    signature: algorithmIdentifier(oid[params.type][signNum]),
    issuer: tripletBuilder(tag.SEQUENCE, issuerParams),
    validity: validity(getValidity(params?.validity)),
    subject: tripletBuilder(tag.SEQUENCE, subjectParams),
    subjectPublicKeyInfo: publicKey.toString('hex'),
    extensions,
  }
}

function external(params) {
  const keys = getKeys(readFileSync(params.key))
  const cert = getCert(readFileSync(params.cert))
  const hashPubKey = getHashPubKey(keys.publicObj.export({type: 'spki',  format: 'der'}))

  return {
    ...keys,
    ...getTbs(cert),
    extensions: {
      authorityKeyIdentifier: authorityKeyIdentifier(hashPubKey),
    },
  }
}

function version(num) {
  if (![0, 1, 2].includes(num)) throw new Error('the version can be 0,1,2')
  return tripletBuilder(context(0, true), tripletBuilder(tag.INTEGER, toHex(num)))
}

function serialNumber(num) {
  return tripletBuilder(tag.INTEGER, !isNaN(num) ? toHex(num) : toHex(Date.now()))
}

function algorithmIdentifier(oid) {
  const data =  [tripletBuilder(tag.OBJECTIDENTIFIER, oidBuilder(oid))]
  if (oid.includes('113549.1.1')) data.push(tripletBuilder(tag.NULL))

  return tripletBuilder(tag.SEQUENCE, data)
}

function relativeDistinguishedName(oid, data) {
  let t, d
  if (oid == '2.5.4.6') {
    t = tag.PRINTABLESTRING
    d = toHex(data)
  } else {
    t = tag.UTF8STRING
    d = toHex(data)
  }

  return tripletBuilder(tag.SET, tripletBuilder(tag.SEQUENCE, [
    tripletBuilder(tag.OBJECTIDENTIFIER, oidBuilder(oid)),
    tripletBuilder(t, d),
  ]))
}

function subjectAltName(data) {
  // https://datatracker.ietf.org/doc/html/rfc5280#page-38
  const params = data.map(([type, value]) => {
    if (type == 'iPAddress') return tripletBuilder(context(gnType[type], false), ipAltName(value))
    else return tripletBuilder(context(gnType[type], false), toHex(value))
  })

  return tripletBuilder(tag.SEQUENCE, [
    tripletBuilder(tag.OBJECTIDENTIFIER, oidBuilder(oid.extensions.subjectAltName)),
    tripletBuilder(tag.OCTETSTRING, tripletBuilder(tag.SEQUENCE, params))
  ])
}

function validity(datePackage) {
  return tripletBuilder(tag.SEQUENCE, [
    tripletBuilder(tag.GENERALIZEDTIME, toHex(datePackage.notBefore)),
    tripletBuilder(tag.GENERALIZEDTIME, toHex(datePackage.notAfter)),
  ])
}

function basicConstraints() {
  return tripletBuilder(tag.SEQUENCE, [
    tripletBuilder(tag.OBJECTIDENTIFIER, oidBuilder(oid.extensions.basicConstraints)),
    tripletBuilder(tag.BOOLEAN, toHex(0xFF)),
    tripletBuilder(tag.OCTETSTRING, tripletBuilder(tag.SEQUENCE, 
      tripletBuilder(tag.BOOLEAN, toHex(0xFF))
    )),
  ])
}

function authorityKeyIdentifier(hashPubKey) {
  return tripletBuilder(tag.SEQUENCE, [
    tripletBuilder(tag.OBJECTIDENTIFIER, oidBuilder(oid.extensions.authorityKeyIdentifier)),
    tripletBuilder(tag.OCTETSTRING, tripletBuilder(tag.SEQUENCE, 
      tripletBuilder(context(0, false), hashPubKey)
    )),
  ])
}

function subjectKeyIdentifier(hashPubKey) {
  return tripletBuilder(tag.SEQUENCE, [
    tripletBuilder(tag.OBJECTIDENTIFIER, oidBuilder(oid.extensions.subjectKeyIdentifier)),
    tripletBuilder(tag.OCTETSTRING, tripletBuilder(tag.OCTETSTRING, hashPubKey)),
  ])
}

function tags() {
  return {
    'NULL'             : 0x05,
    'SEQUENCE'         : 0x30,
    'SET'              : 0x31,
    'OBJECTIDENTIFIER' : 0x06,
    'INTEGER'          : 0x02,
    'BITSTRING'        : 0x03,
    'OCTETSTRING'      : 0x04,
    'UTF8STRING'       : 0x0C,
    'PRINTABLESTRING'  : 0x13,
    'IA5STRING'        : 0x16,
    'UTCTIME'          : 0x17,
    'GENERALIZEDTIME'  : 0x18,
    'BOOLEAN'          : 0x01,
  }
}

function oids() {
  return {
    ecdsa: {
      1   :   '1.2.840.10045.4.1',   // ecdsaWithSHA1
      256 : '1.2.840.10045.4.3.2',   // ecdsaWithSHA256
      384 : '1.2.840.10045.4.3.3',   // ecdsaWithSHA384
      512 : '1.2.840.10045.4.3.4',   // ecdsaWithSHA512
    },
    rsa: {
      1   :  '1.2.840.113549.1.1.5', // sha1WithRSAEncryption
      256 : '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
      384 : '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
      512 : '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
    },
    subject: {
      'commonName'              : '2.5.4.3',
      'countryName'             : '2.5.4.6',
      'stateOrProvinceName'     : '2.5.4.8',
      'organizationName'        : '2.5.4.10',
      'organizationalUnitName'  : '2.5.4.11',
    },
    extensions: {
      'subjectAltName'          : '2.5.29.17',
      'issuerAltName'           : '2.5.29.18',
      'subjectKeyIdentifier'    : '2.5.29.14',
      'keyUsage'                : '2.5.29.15',
      'basicConstraints'        : '2.5.29.19',
      'authorityKeyIdentifier'  : '2.5.29.35',
      'extKeyUsage'             : '2.5.29.37',
    }
  }
}

function gnTypes() {
  return {
  //'otherName'                 : 0, // AnotherName,
    'rfc822Name'                : 1, // IA5String,
    'dNSName'                   : 2, // IA5String,
  //'x400Address'               : 3, // ORAddress,
  //'directoryName'             : 4, // Name,
  //'ediPartyName'              : 5, // EDIPartyName,
    'uniformResourceIdentifier' : 6, // IA5String,
    'iPAddress'                 : 7, // OCTET STRING,
  //'registeredID'              : 8, // OBJECT IDENTIFIER
  }
}

function tripletBuilder(tag, hexArr) {
  if (tag == 5) return '0500'

  if (!Array.isArray(hexArr)) hexArr = [hexArr]

  if (hexArr.filter(h => !/[a-fA-F0-9]{2}/g.test(h)).length)
    throw new Error('maybe the data is not in hex format')

  const length  = hexArr.reduce((len, d) => len += d.length / 2, 0)
  const hLength = toHex(length)
  const lengthLength = hLength.length / 2

  let triplet = ''

  triplet += toHex(tag)

  if (length <= 127)
    triplet += hLength
  else 
    triplet += toHex(parseInt(80 + lengthLength, 16)) + hLength

  for (const hex of hexArr) {
    triplet += hex
  }

  return triplet
}

function context(context, isConstructed) {
  // Class: Context-specific
  const b1 = isConstructed ? [7, 5] : [7]
  const b0 = isConstructed ? [6]    : [6]

  b1.forEach(pos => context |= 1 << pos)
  b0.forEach(pos => context &= ~(1 << pos))

  return context
}


function oidBuilder(data) {
  const octArr = data.split('.')

  return octArr.reduce((a, o, i, ar) => {
    if (i == 0) return a
    o = parseInt(o, 10)
    if (i == 1) o = parseInt(ar[0], 10) * 40 + o
    return a += _exec(o)
  }, '')

  function _exec(num) {
    const base = 128
    let binArr
    let shift = 0

    while (true) {
      const {mantissa, exponent} = intParts(num, base)
      num = num - Math.trunc(mantissa) * Math.pow(base, exponent)
      if (!shift) binArr = new Array(exponent + 1).fill(0)
      binArr[shift] = Math.trunc(mantissa)
      shift++
      if (!exponent) break
    }

    return binArr.map((b, i, a) => {
      if (i < a.length - 1) return toHex(b |= 1 << 7)
      return toHex(b)
    }).join('')
  }
}

function intParts(x, b) {
  // https://stackoverflow.com/a/30690986
  var exp = 0
  var sgn = 0

  if (x === 0) return {sign: 0, mantissa: 0, exponent: 0}
  if (x < 0) sgn = 1, x = -x

  while (x > b) x /= b, exp++
  while (x < 1) x *= b, exp--

  if (1/x ===  Infinity) return {sign: 0, mantissa: 0, exponent: 0}
  if (1/x === -Infinity) return {sign: 1, mantissa: 0, exponent: 0}

  return {sign: sgn, mantissa: x, exponent: exp}
}

function toHex(data) {
  if (['number', 'bigint'].includes(typeof data)) {
    const d = Math.abs(parseInt(data))
    data = BigInt(data)
    const byte = Math.ceil(Math.log2(d < 2 ? 2 : d) / 8)
  
    if (data >= -9223372036854775808n && data <= 18446744073709551615n) {
      const buf = Buffer.alloc(8)

      if (data > 9223372036854775807n) buf.writeBigUint64BE(data)
      else buf.writeBigInt64BE(data)
      
      return buf.subarray(8 - byte, 8).toString('hex')
    } else {
      throw new Error('a number greater than or less than the allowed value')
    }
  } else if (typeof data == 'string') {
    return Buffer.from(data, 'utf8').toString('hex')
  } else throw new Error('it is possible to get hex from a string or a number')
}

function getTbs(buff) {
  let shift = 0
  const out = {}
  const fields = [
    {f:'version', t: 'a0'},
    {f:'serialNumber', t: '02'},
    {f:'signature', t: '30'},
    {f:'issuer', t: '30'},
    {f:'validity', t: '30'},
    {f:'subject', t: '30'},
    {f:'subjectPublicKeyInfo', t: '30'},
  ]
  
  shift++ // tag
  const s1 = buff.subarray(shift, shift + 1).readUint8()
  shift += s1 > 128 ? 1 + (s1 - 128) : 1 // size
  shift++ // tag
  const s2 = buff.subarray(shift, shift + 1).readUint8()
  shift += s1 > 128 ? 1 + (s2 - 128) : 1 // size

  for (const {f, t} of fields) {
    let {block, endByte} = _block(shift)
    
    if (f == 'version' && block.slice(0, 2) != 'a0') {
      endByte = shift
      block = 'a003020100'
    }

    _error(block, t)
    shift = endByte
    out[f] = block
  }

  return out
  
  function _block(shift) {
    let shiftCount = shift
    shiftCount++ // tag
    const size = buff.subarray(shiftCount, shiftCount + 1).readUint8()
    const sizeSize = size > 128 ? size - 128 : 1 // size

    const end = sizeSize == 1 
      ? shiftCount + sizeSize + buff.subarray(shiftCount, shiftCount + 1).readUint8()
      : shiftCount + 1 + sizeSize + buff.subarray(shiftCount + 1, shiftCount + 1 + sizeSize).readUint16BE()

    return {
      block: buff.subarray(shift, end).toString('hex'),
      endByte: end,
    }
  }

  function _error(data, tag) {
    if (data.slice(0, 2) != tag)
      throw new Error('error reading the certificate structure')
  }
}

function getKeys(buff) {
  const param = [
    {format: 'pem'},
    //{format: 'jwk'}, // v8 exception
    {format: 'der', type: 'pkcs8'},
    {format: 'der', type: 'spki'},
    {format: 'der', type: 'pkcs1'}, 
    {format: 'der', type: 'sec1'},
  ]

  let privObj
  for (const p of param) {
    try {
      privObj = createPrivateKey({key: buff, ...p})
      break
    } catch(e) {
      if (
        !e?.opensslErrorStack 
        && !['ERR_INVALID_ARG_VALUE', 'ERR_OSSL_UNSUPPORTED'].includes(e.code)
      ) throw new Error(e)
    }
  }

  let pubObj
  for (const p of param) {
    try {
      pubObj = createPublicKey({key: buff, ...p})
      break
    } catch(e) {
      if (
        !e?.opensslErrorStack 
        && !['ERR_INVALID_ARG_VALUE', 'ERR_OSSL_UNSUPPORTED'].includes(e.code)
      ) throw new Error(e)
    }
  }

  if (!privObj) throw new Error('the external private key was not received')
  if (!pubObj)  throw new Error('the external public key was not received')

  return {
    privateObj: privObj,
    publicObj:  pubObj,
  }
}

function getCert(buff) {
  try {
    const certObj = new X509Certificate(buff)
    return certObj.raw
  } catch (error) {
    const msg = `>> certificate structure error <<\n`
    + `message: ${error.message}\n`
    + `reason: ${error.reason}\n`
    + `code: ${error.code}\n`
    throw new Error(msg)
  }
}

function getHashPubKey(pubKeyDer) {
  let shift = 0
  shift++ // tag
  const s1 = pubKeyDer.subarray(shift, shift + 1).readUint8()
  shift += s1 > 128 ? 1 + (s1 - 128) : 1 // size
  shift++ // tag
  const s2 = pubKeyDer.subarray(shift, shift + 1).readUint8()
  shift += 1 + s2 // size + data size
  shift++ // tag
  const s3 = pubKeyDer.subarray(shift, shift + 1).readUint8()
  shift += s3 > 128 ? 1 + (s3 - 128) : 1 // size
  shift++ // tech byte
  const data = pubKeyDer.subarray(shift, pubKeyDer.byteLength)
  return createHash('SHA1').update(data).digest('hex')
}

function isObject(subj) {
  return subj === Object(subj) && Object.prototype.toString.call(subj) == '[object Object]'
}

function getValidity(params) {
  const {notBefore, notAfter} = params ?? {}
  const currentObj   = new Date()
  const notBeforeInt = notBefore ? new Date(notBefore).getTime() : currentObj.getTime()
  const notAfterInt  = notAfter ? new Date(notAfter).getTime() : currentObj.setFullYear(currentObj.getFullYear() + 1)

  return {
    notBefore: _toGeneralizedTime(notBeforeInt),
    notAfter:  _toGeneralizedTime(notAfterInt)
  }

  function _toGeneralizedTime(int) {
    return new Date(int).toISOString().replace(/[-T:]/g, '').split('.')[0] + 'Z'
  }
}

function ipAltName(ip) {
  ip = ip.split('/')[0]
  const is4 = ip.includes('.')
  const is6 = ip.includes(':')

  if (!ip.split('.').length == 4 && !ip.split(':').length == 8) 
    throw new Error('only full IP addresses are allowed')

  if (is4) return ip.split('.').map(n => toHex(parseInt(n, 10))).join('')
  if (is6) return ip.replaceAll(':', '')
  throw new Error('failed to convert ip address')
}

function printCert(hex) {
  const arr = Buffer.from(hex, 'hex').toString('base64').match(/.{0,64}/g)
  
  return ''
    + '-----BEGIN CERTIFICATE-----\n'
    + arr.join('\n')
    + '-----END CERTIFICATE-----\n'
}

function saveFile(flag, type, pairObj, path) {
  flag = flag ? flag + '_' : ''
  type = type ? type + '_' : ''
  const certBuff = getCert(pairObj.cert)

  writeFileSync(`${path}/${flag}${type}certificate.pem`, pairObj.cert, {flag: 'wx'})
  writeFileSync(`${path}/${flag}${type}certificate.crt`, certBuff,     {flag: 'wx'})
  writeFileSync(`${path}/${flag}${type}private.pem`,     pairObj.key,  {flag: 'wx'})
}
