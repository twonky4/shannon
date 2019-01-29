/* jshint -W097 */// jshint strict:false
/*jslint node: true */

const expect = require('chai').expect;
const key = [0x65, 0x87, 0xd8, 0x8f, 0x6c, 0x32, 0x9d, 0x8a, 0xe4, 0x6b];
const Shannon = require(__dirname + '/../main');

describe('Test Shannon', function() {
    it('Test Shannon Encrypt', function (done) {
        this.timeout(1000);

        let plaintext = 'Hello World';

        let s = new Shannon(key);
        let encryptedtext = s.encrypt(plaintext);
        let mac = s.finish(Buffer.alloc(16));

        expect(encryptedtext).to.deep.equal(Buffer.from([0x94, 0x81, 0xe5, 0xa9, 0x5f, 0x93, 0x5e, 0xcb, 0x6c, 0xb5, 0x24]));
        expect(mac).to.deep.equal(Buffer.from([0x43, 0x23, 0x86, 0x24, 0xf3, 0xc9, 0x0c, 0x58, 0x79, 0xf4, 0xd3, 0xef, 0x83, 0x98, 0x2e, 0x4e]));

        done();
    });

    it('Test Shannon Decrypt', function (done) {
        this.timeout(1000);

    	let encryptedtext = Buffer.from([0x94, 0x81, 0xe5, 0xa9, 0x5f, 0x93, 0x5e, 0xcb, 0x6c, 0xb5, 0x24]);
    	let mac = Buffer.from([0x43, 0x23, 0x86, 0x24, 0xf3, 0xc9, 0x0c, 0x58, 0x79, 0xf4, 0xd3, 0xef, 0x83, 0x98, 0x2e, 0x4e]);

        let s = new Shannon(key);
        let buf = s.decrypt(encryptedtext);
        let expectedMac = s.finish(Buffer.alloc(16));

        expect(Buffer.from('Hello World')).to.deep.equal(buf);
        expect(mac).to.deep.equal(expectedMac);

        done();
    });
});
