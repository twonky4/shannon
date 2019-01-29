# shannon 
[![Build Status](https://travis-ci.org/twonky4/shannon.svg?branch=master)](https://travis-ci.org/twonky4/shannon)

Pure javascript implementation of Shannon stream cipher. No-brainer port of [shannon](https://github.com/chatoooo/shannon).

Shannon cipher is used in Spotify Connect to encrypt communication between player and Spotify AP server. Shannon cipher
is variant of [Sober](https://en.wikipedia.org/wiki/SOBER) stream cipher.

## Example
Encryption
```javascript
const Shannon = require('shannon');
...
let key = Buffer.from([0x65, 0x87, 0xd8, 0x8f, 0x6c, 0x32, 0x9d, 0x8a, 0xe4, 0x6b]);
let message = 'My secret message';

let cipher = new Shannon(key);
let message = cipher.encrypt(message);
// message contains ciphertext now
let mac = cipher.final(Buffer.alloc(16));
// mac contains MAC of the message
```

Decryption
```javascript
const Shannon = require('shannon');
...
let key = Buffer.from([0x65, 0x87, 0xd8, 0x8f, 0x6c, 0x32, 0x9d, 0x8a, 0xe4, 0x6b]);
// message is encrypted
let message = Buffer.from([0x91, 0x9d, 0xa9, 0xb6, 0x29, 0xfc, 0x9c, 0xdd, 0x17, 0x8c, 0x15, 0x31, 0x9a, 0xae, 0xcc, 0x6e, 0xd4]);
let receivedMac = Buffer.from([0xbe, 0x7b, 0xef, 0x39, 0xee, 0xfe, 0x54, 0xfd, 0x8d, 0xb0, 0xbc, 0x6f, 0xd5, 0x30, 0x35, 0x19]);
let cipher = new Shannon(key);
let message = cipher.decrypt(message);
// message contains plaintext now
let mac = cipher.final(Buffer.alloc(16));
if (Buffer.compare(mac, receivedMac)) {
	console.log("MAC OK")
}
```