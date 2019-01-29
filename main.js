/* jshint -W097 */
// jshint strict:false
/*jslint node: true */
'use strict';

/**
 * Implementation of the Shannon stream-cipher.
 *
 * Based on original reference implementation in C.
 *
 * @author Felix Bruns <felixbruns@web.de>
 */
function Shannon(options) {
	let self = this;

	/*
	 * Fold is how many register cycles need to be performed after combining the
	 * last byte of key and non-linear feedback, before every byte depends on every
	 * byte of the key. This depends on the feedback and nonlinear functions, and
	 * on where they are combined into the register. Making it same as the register
	 * length is a safe and conservative choice.
	 */
	const N = 16;
	const FOLD = N; // How many iterations of folding to do.
	const INITKONST = 0x6996c53a; // Value of konst to use during key loading.
	const KEYP = 13; // Where to insert key/MAC/counter words.

	let _initArray = function(n) {
		let a = new Array(n);
		for(let i = 0; i < n;i++) {
			a[i] = 0;
		}
		return a;
	}

	let R = _initArray(N); // Working storage for the shift register.
	let CRC = _initArray(N); // Working storage for CRC accumulation.
	let initR = _initArray(N); // Saved register contents.
	let konst = 0; // Key dependant semi-constant.
	let sbuf = 0;  // Encryption buffer.
	let mbuf = 0;  // Partial word MAC buffer.
	let nbuf = 0;  // Number of part-word stream bits buffered.

	let _rotateLeft = function (i, distance) {
        return (i << distance) | (i >>> -distance);
    }

	let _bufferToArray = function(buffer) {
		if(typeof buffer === 'string' || buffer instanceof String) {
			buffer = Buffer.from(buffer);
		}
		if(Buffer.isBuffer(buffer)) {
			let arr = new Array();
			arr.push(...buffer);
			buffer = arr;
		}

		return buffer;
	}

	/**
	 * Nonlinear transform (sbox) of a word. There are two slightly different combinations.
	 */
	let sbox = function(i) {
		i ^= _rotateLeft(i, 5) | _rotateLeft(i, 7);
		i ^= _rotateLeft(i, 19) | _rotateLeft(i, 22);

		return i;
	}

	let sbox2 = function(i) {
		i ^= _rotateLeft(i, 7) | _rotateLeft(i, 22);
		i ^= _rotateLeft(i, 5) | _rotateLeft(i, 19);

		return i;
	}

	/**
	 * Cycle the contents of the register and calculate output word in sbuf.
	 */
	let cycle = function() {
		// Temporary variable.
		let t = 0;

		// Nonlinear feedback function.
		t = R[12] ^ R[13] ^ konst;
		t = sbox(t) ^ _rotateLeft(R[0], 1);

		// Shift register.
		for(let i = 1; i < N; i++) {
			R[i - 1] = R[i];
		}

		R[N - 1] = t;

		t = sbox2(R[2] ^ R[15]);
		R[0] ^= t;
		sbuf = t ^ R[8] ^ R[12];
	}

	/*
	 * The Shannon MAC function is modelled after the concepts of Phelix and SHA.
	 * Basically, words to be accumulated in the MAC are incorporated in two
	 * different ways:
	 * 1. They are incorporated into the stream cipher register at a place
	 *    where they will immediately have a nonlinear effect on the state.
	 * 2. They are incorporated into bit-parallel CRC-16 registers; the
	 *    contents of these registers will be used in MAC finalization.
	 */

	/**
	 * Accumulate a CRC of input words, later to be fed into MAC.
	 * This is actually 32 parallel CRC-16s, using the IBM CRC-16
	 * polynomian x^16 + x^15 + x^2 + 1
	 */
	let crcFunc = function(i) {
		// Temporary variable.
		let t = 0;

		// Accumulate CRC of input.
		t = CRC[0] ^ CRC[2] ^ CRC[15] ^ i;

		for(let j = 1; j < N; j++) {
			CRC[j - 1] = CRC[j];
		}

		CRC[N - 1] = t;
	}

	/**
	 * Normal MAC word processing: do both stream register and CRC.
	 */
	let macFunc = function(i) {
		crcFunc(i);

		R[KEYP] ^= i;
	}

	/**
	 * Initialize to known state.
	 */
	let initState = function() {
		// Register initialized to Fibonacci numbers.
		R[0] = 1;
		R[1] = 1;

		for(let i = 2; i < N; i++) {
			R[i] = R[i - 1] + R[i - 2];
		}

		// Initialization constant.
		konst = INITKONST;
	}

	/**
	 * Save the current register state.
	 */
	let saveState = function() {
		for(let i = 0; i < N; i++) {
			initR[i] = R[i];
		}
	}

	/**
	 * Inisialize to previously saved register state.
	 */
	let reloadState = function() {
		for(let i = 0; i < N; i++) {
			R[i] = initR[i];
		}
	}

	/**
	 * Initialize 'konst'.
	 */
	let genKonst = function() {
		konst = R[0];
	}

	/**
	 * Load key material into the register.
	 */
	let addKey = function(k) {
		R[KEYP] ^= k;
	}

	/**
	 * Extra nonlinear diffusion of register for key and MAC.
	 */
	let diffuse = function() {
		for(let i = 0; i < FOLD; i++) {
			cycle();
		}
	}

	/**
	 * Common actions for loading key material.
	 * Allow non-word-multiple key and nonce material.
	 * Note: Also initializes the CRC register as a side effect.
	 */
	let loadKey = function(_key) {
		let extra = _initArray(4);
		let i = 0;
		let j = 0;
		let t = 0;

		// Start folding key.
		for(i = 0; i < (_key.length & ~0x03); i += 4) {
			// Shift 4 bytes into one word.
			t =	((_key[i + 3] & 0xFF) << 24) |
				((_key[i + 2] & 0xFF) << 16) |
				((_key[i + 1] & 0xFF) << 8) |
				((_key[i] & 0xFF));

			// Insert key word at index 13.
			addKey(t);

			// Cycle register.
			cycle();
		}

		// If there were any extra bytes, zero pad to a word.
		if(i < _key.length) {
			// i remains unchanged at start of loop.
			for(j = 0; i < _key.length; i++) {
				extra[j++] = _key[i];
			}

			// j remains unchanged at start of loop.
			for(; j < 4; j++) {
				extra[j] = 0;
			}

			// Shift 4 extra bytes into one word.
			t =	((extra[3] & 0xFF) << 24) |
				((extra[2] & 0xFF) << 16) |
				((extra[1] & 0xFF) << 8) |
				((extra[0] & 0xFF));

			// Insert key word at index 13.
			addKey(t);

			// Cycle register.
			cycle();
		}

		// Also fold in the length of the key.
		addKey(_key.length);

		// Cycle register.
		cycle();

		// Save a copy of the register.
		for(i = 0; i < N; i++) {
			CRC[i] = R[i];
		}

		// Now diffuse.
		diffuse();

		// Now XOR the copy back -- makes key loading irreversible.
		for(i = 0; i < N; i++) {
			R[i] ^= CRC[i];
		}
	}

	/**
	 * Set key
	 */
	let key = function(_key) {
		_key = _bufferToArray(_key);

		// Initializet known state.
		initState();

		// Load key material.
		loadKey(_key);

		// In case we proceed to stream generation.
		genKonst();

		// Save register state.
		saveState();

		// Set 'nbuf' value to zero.
		nbuf = 0;
	}

	/**
	 * Set IV
	 */
	let nonce = function(_nonce) {
		_nonce = _bufferToArray(_nonce);

		// Reload register state.
		reloadState();

		// Set initialization constant.
		konst = INITKONST;

		// Load "IV" material.
		loadKey(_nonce);

		// Set 'konst'.
		genKonst();

		// Set 'nbuf' value to zero.
		nbuf = 0;
	}

	/**
	 * XOR pseudo-random bytes into buffer.
	 * Note: doesn't play well with MAC functions.
	 */
	let stream = function(buffer) {
		buffer = _bufferToArray(buffer);

		let i = 0;
		let j = 0;
		let n = buffer.length;

		// Handle any previously buffered bytes.
		while(nbuf != 0 && n != 0) {
			buffer[i++] ^= sbuf & 0xFF;

			sbuf >>= 8;
			nbuf -= 8;

			n--;
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			cycle();

			// XOR word.
			buffer[i + 3] ^= (sbuf >> 24) & 0xFF;
			buffer[i + 2] ^= (sbuf >> 16) & 0xFF;
			buffer[i + 1] ^= (sbuf >>  8) & 0xFF;
			buffer[i] ^= (sbuf) & 0xFF;

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			cycle();

			nbuf = 32;

			while(nbuf != 0 && n != 0) {
				buffer[i++] ^= sbuf & 0xFF;

				sbuf >>= 8;
				nbuf -= 8;

				n--;
			}
		}

		return Buffer.from(buffer);
	}

	/**
	 * Accumulate words into MAC without encryption.
	 * Note that plaintext is accumulated for MAC.
	 */
	let macOnly = function(buffer) {
		buffer = _bufferToArray(buffer);

		let i = 0;
		let j = 0;
		let n = buffer.length;
		let t = 0;

		// Handle any previously buffered bytes.
		if(nbuf != 0) {
			while(nbuf != 0 && n != 0) {
				mbuf ^= buffer[i++] << (32 - nbuf);
				nbuf -= 8;

				n--;
			}

			// Not a whole word yet.
			if(nbuf != 0) {
				return Buffer.from(buffer);
			}

			// LFSR already cycled.
			macFunc(mbuf);
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			cycle();

			// Shift 4 bytes into one word.
			t =	((buffer[i + 3] & 0xFF) << 24) |
				((buffer[i + 2] & 0xFF) << 16) |
				((buffer[i + 1] & 0xFF) << 8) |
				((buffer[i] & 0xFF));

			macFunc(t);

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			cycle();

			mbuf = 0;
			nbuf = 32;

			while(nbuf != 0 && n != 0) {
				mbuf ^= buffer[i++] << (32 - nbuf);
				nbuf -= 8;

				n--;
			}
		}

		return Buffer.from(buffer);
	}

	/**
	 * Combined MAC and encryption.
	 * Note that plaintext is accumulated for MAC.
	 */
	let encrypt = function(buffer, n) {
		buffer = _bufferToArray(buffer);
		if(n == null) {
			n = buffer.length;
		}
		let i = 0;
		let j = 0;
		let t = 0;

		// Handle any previously buffered bytes.
		if(nbuf != 0) {
			while(nbuf != 0 && n != 0) {
				mbuf ^= (buffer[i] & 0xFF) << (32 - nbuf);
				buffer[i] ^= (sbuf >> (32 - nbuf)) & 0xFF;

				i++;

				nbuf -= 8;

				n--;
			}

			// Not a whole word yet.
			if(nbuf != 0) {
				return Buffer.from(buffer);
			}

			// LFSR already cycled.
			macFunc(mbuf);
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			cycle();

			// Shift 4 bytes into one word.
			t =	((buffer[i + 3] & 0xFF) << 24) |
				((buffer[i + 2] & 0xFF) << 16) |
				((buffer[i + 1] & 0xFF) << 8) |
				((buffer[i] & 0xFF));

			macFunc(t);

			t ^= sbuf;

			// Put word into byte buffer.
			buffer[i + 3] = (t >> 24) & 0xFF;
			buffer[i + 2] = (t >> 16) & 0xFF;
			buffer[i + 1] = (t >>  8) & 0xFF;
			buffer[i] = (t) & 0xFF;

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			cycle();

			mbuf = 0;
			nbuf = 32;

			while(nbuf != 0 && n != 0) {
				mbuf ^= (buffer[i] & 0xFF) << (32 - nbuf);
				buffer[i] ^= (sbuf >> (32 - nbuf)) & 0xFF;

				i++;

				nbuf -= 8;

				n--;
			}
		}

		return Buffer.from(buffer);
	}

	/**
	 * Combined MAC and decryption.
	 * Note that plaintext is accumulated for MAC.
	 */
	let decrypt = function(buffer, n) {
		buffer = _bufferToArray(buffer);
		if(n == null) {
			n = buffer.length;
		}
		let i = 0;
		let j = 0;
		let t = 0;

		// Handle any previously buffered bytes.
		if(nbuf != 0) {
			while(nbuf != 0 && n != 0) {
				buffer[i] ^= (sbuf >> (32 - nbuf)) & 0xFF;
				mbuf ^= (buffer[i] & 0xFF) << (32 - nbuf);

				i++;

				nbuf -= 8;

				n--;
			}

			// Not a whole word yet.
			if(nbuf != 0) {
				return Buffer.from(buffer);
			}

			// LFSR already cycled.
			macFunc(mbuf);
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			cycle();

			// Shift 4 bytes into one word.
			t =	((buffer[i + 3] & 0xFF) << 24) |
				((buffer[i + 2] & 0xFF) << 16) |
				((buffer[i + 1] & 0xFF) << 8) |
				((buffer[i] & 0xFF));

			t ^= sbuf;

			macFunc(t);

			// Put word into byte buffer.
			buffer[i + 3] = (t >> 24) & 0xFF;
			buffer[i + 2] = (t >> 16) & 0xFF;
			buffer[i + 1] = (t >>  8) & 0xFF;
			buffer[i] = (t) & 0xFF;

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			cycle();

			mbuf = 0;
			nbuf = 32;

			while(nbuf != 0 && n != 0) {
				buffer[i] ^= (sbuf >> (32 - nbuf)) & 0xFF;
				mbuf ^= (buffer[i] & 0xFF) << (32 - nbuf);

				i++;

				nbuf -= 8;

				n--;
			}
		}

		return Buffer.from(buffer);
	}

	/**
	 * Having accumulated a MAC, finish processing and return it.
	 * Note that any unprocessed bytes are treated as if they were
	 * encrypted zero bytes, so plaintext (zero) is accumulated.
	 */
	let finish = function(buffer, n) {
		buffer = _bufferToArray(buffer);
		if(n == null) {
			n = buffer.length;
		}
		let i = 0;
		let j = 0;

		// Handle any previously buffered bytes.
		if(nbuf != 0) {
			// LFSR already cycled.
			macFunc(mbuf);
		}

		/**
		 * Perturb the MAC to mark end of input.
		 * Note that only the stream register is updated, not the CRC.
		 * This is an action that can't be duplicated by passing in plaintext,
		 * hence defeating any kind of extension attack.
		 */
		cycle();
		addKey(INITKONST ^ (nbuf << 3));

		nbuf = 0;

		// Now add the CRC to the stream register and diffuse it.
		for(j = 0; j < N; j++) {
			R[j] ^= CRC[j];
		}

		diffuse();

		// Produce output from the stream buffer.
		while(n > 0) {
			cycle();

			if(n >= 4) {
				// Put word into byte buffer.
				buffer[i + 3] = (sbuf >> 24) & 0xFF;
				buffer[i + 2] = (sbuf >> 16) & 0xFF;
				buffer[i + 1] = (sbuf >>  8) & 0xFF;
				buffer[i] = (sbuf) & 0xFF;

				n -= 4;
				i += 4;
			} else {
				for(j = 0; j < n; j++) {
					buffer[i + j] = (sbuf >> (i * 8)) & 0xFF;
				}

				break;
			}
		}

		return Buffer.from(buffer);
	}

	self.key = key;
	self.nonce = nonce;
	self.stream = stream;
	self.macOnly = macOnly;
	self.encrypt = encrypt;
	self.decrypt = decrypt;
	self.finish = finish;

	if(options != null) {
		key(options);
	}
}

module.exports = Shannon;
