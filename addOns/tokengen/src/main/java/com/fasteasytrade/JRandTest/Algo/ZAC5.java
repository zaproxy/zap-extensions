/*
 * Created on 12/04/2005
 *
 * JRandTest package
 *
 * Copyright (c) 2005, Zur Aougav, aougav@hotmail.com
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list 
 * of conditions and the following disclaimer. 
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this 
 * list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution. 
 * 
 * Neither the name of the JRandTest nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without specific 
 * prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.fasteasytrade.JRandTest.Algo;

import java.util.Random;

/**
 * ZAC5 encryption algorithm Copyright (c) 2005 Zur Aougav
 * <p>
 * Symetric algorithm.
 * <p>
 * Use 5 ARC4 keys:
 * <ul>
 * <li>prePermutationKey to permute input buffer before encryption begins
 * <li>cryptKey to encrypt input bytes,
 * <li>fillKey to add bytes to output,
 * <li>controlKey to control swapping between each two bytes - ciphered byte
 * and fill byte.
 * <li>postPermutationKey to permute ciphered output buffer after encryption
 * </ul>
 * <p>
 * Hence, ciphered text length is double input's length.
 * <p>
 * Before encryption starts, each key is skipped a random number of times (with
 * 4096 <= skip <= 69631). SHA1 digest message (20 bytes) is calculated from the
 * invisible key output. The 20 bytes should be written at the header of the
 * ciphered message/file. Of course, decryption does the reverse, read the hash
 * 20 bytes, and step each key with a check if digest message arrived at is the
 * correct one. Hence, the random number of steps is never exposed directly, but
 * the hash contains implicitly the correct position.
 * 
 * @author Zur Aougav
 */
public class ZAC5 extends Cipher {

	/**
	 * encrypt and decrypt data using cryptKey
	 */
	RC4Key cryptKey;

	/**
	 * add one byte for each encrypt data byte
	 */
	RC4Key fillKey;

	/**
	 * controlKey gives one byte to enable swap of encrypt data and fill data
	 * (from fillKey)
	 */
	RC4Key controlKey;

	/**
	 * prePermutationKey permutes input buffer before encryption begins
	 */
	RC4Key prePermutationKey;

	/**
	 * postPermutationKey permutes ciphered output buffer after encryption
	 * completed
	 */
	RC4Key postPermutationKey;

	/**
	 * cryptKey is processed cryptSkip times, and prng data is hashed using
	 * sha1. Digest "message" is kept in cryptShaDigest.
	 */
	byte[] cryptShaDigest;

	/**
	 * fillKey is processed fillSkip times, and prng data is hashed using sha1.
	 * Digest "message" is kept in fillShaDigest.
	 */
	byte[] fillShaDigest;

	/**
	 * controlKey is processed controlSkip times, and prng data is hashed using
	 * sha1. Digest "message" is kept in controlShaDigest.
	 */
	byte[] controlShaDigest;

	/**
	 * prePermutationKey is processed prePermutationSkip times, and prng data is
	 * hashed using sha1. Digest "message" is kept in prePermutationShaDigest.
	 */
	byte[] prePermutationShaDigest;

	/**
	 * postPermutationKey is processed postPermutationSkip times, and prng data
	 * is hashed using sha1. Digest "message" is kept in
	 * postPermutationShaDigest.
	 */
	byte[] postPermutationShaDigest;

	/**
	 * Original key bytes buffer for cryptKey
	 */
	byte[] cryptBuf;

	/**
	 * Original key bytes buffer for fillKey
	 */
	byte[] fillBuf;

	/**
	 * Original key bytes buffer for controlKey
	 */
	byte[] controlBuf;

	/**
	 * Original key bytes buffer for prePermutationKey
	 */
	byte[] prePermutationBuf;

	/**
	 * Original key bytes buffer for postPermutationKey
	 */
	byte[] postPermutationBuf;

	/**
	 * random number we skip cryptKey before start using it.
	 */
	int cryptSkip;

	/**
	 * random number we skip fillKey before start using it.
	 */
	int fillSkip;

	/**
	 * random number we skip controlKey before start using it.
	 */
	int controlSkip;

	/**
	 * random number we skip prePermutationKey before start using it.
	 */
	int prePermutationSkip;

	/**
	 * random number we skip postPermutationKey before start using it.
	 */
	int postPermutationSkip;

	/**
	 * Boolean flag if we ever find an incorrect fill byte in data.
	 * <p>
	 * Only used while decryption.
	 * <p>
	 * If true, we fill (silently) all output data with random data from rnd
	 * variable.
	 */
	boolean garbage = false;

	/**
	 * Use java random class to
	 * <ol>
	 * <li>fill new keys
	 * <li>put some garbage bytes in output buffer (if decryption fails).
	 * </ol>
	 */
	java.util.Random rnd = new Random();

	/**
	 * input and output buffers are permuted numCyclesOfPermutations times
	 */
	int numCyclesOfPermutations = 4;

	/**
	 * default constructor - does nothing.
	 *  
	 */
	public ZAC5() {
		super();
	}

	/**
	 * constructor with 5 keys to setup.
	 * 
	 * @param cryptBuf
	 *            kept in obejct cryptBuf and init cryptKey
	 * @param fillBuf
	 *            kept in obejct fillBuf and init fillKey
	 * @param controlBuf
	 *            kept in obejct controlBuf and init controlKey
	 * @param prePermutationBuf
	 *            kept in obejct prePerbutation and init prePermutationKey
	 * @param postPermutationBuf
	 *            kept in obejct postPerbutation and init postPermutationKey
	 */
	public ZAC5(byte[] cryptBuf, byte[] fillBuf, byte[] controlBuf,
			byte[] prePermutationBuf, byte[] postPermutationBuf) {
		setup(cryptBuf, fillBuf, controlBuf, prePermutationBuf,
				postPermutationBuf);
	}

	/**
	 * setup 5 keys to ZAC5 algorithm. If one of the input buffers is null, we
	 * fill it with 256 random bytes.
	 * <p>
	 * keep keys and skip data in object so initEncrypt() and reset() can run
	 * properly.
	 * 
	 * @param cryptBuf
	 *            256 bytes to cryptKey
	 * @param fillBuf
	 *            256 bytes to fillKey
	 * @param controlBuf
	 *            256 bytes to controlKey
	 * @param prePermutationBuf
	 *            256 bytes to prePermutationKey
	 * @param postPermutationBuf
	 *            256 bytes to postPermutationKey
	 */
	public void setup(byte[] cryptBuf, byte[] fillBuf, byte[] controlBuf,
			byte[] prePermutationBuf, byte[] postPermutationBuf) {

		if (cryptBuf == null) {
			cryptBuf = new byte[256];
			rnd.nextBytes(cryptBuf);
		}

		if (fillBuf == null) {
			fillBuf = new byte[256];
			rnd.nextBytes(fillBuf);
		}

		if (controlBuf == null) {
			controlBuf = new byte[256];
			rnd.nextBytes(controlBuf);
		}

		if (prePermutationBuf == null) {
			prePermutationBuf = new byte[256];
			rnd.nextBytes(prePermutationBuf);
		}

		if (postPermutationBuf == null) {
			postPermutationBuf = new byte[256];
			rnd.nextBytes(postPermutationBuf);
		}

		this.cryptBuf = cryptBuf;
		this.fillBuf = fillBuf;
		this.controlBuf = controlBuf;
		this.prePermutationBuf = prePermutationBuf;
		this.postPermutationBuf = postPermutationBuf;

		cryptKey = new RC4Key(cryptBuf, 0, null);
		fillKey = new RC4Key(fillBuf, 0, null);
		controlKey = new RC4Key(controlBuf, 0, null);
		prePermutationKey = new RC4Key(prePermutationBuf, 0, null);
		postPermutationKey = new RC4Key(postPermutationBuf, 0, null);

		cryptSkip = rnd.nextInt(0xffff);
		fillSkip = rnd.nextInt(0xffff);
		controlSkip = rnd.nextInt(0xffff);
		prePermutationSkip = rnd.nextInt(0xffff);
		postPermutationSkip = rnd.nextInt(0xffff);
	}

	/**
	 * init keys, using hash on prng of each key. Digest message generated from
	 * key xyz is kept as xyzShaDigest variable.
	 * <p>
	 * initEncrypt method is run before encryption starts.
	 */
	public void initEncrypt() {
		int i;
		com.fasteasytrade.JRandTest.Algo.SHA1 sha = new com.fasteasytrade.JRandTest.Algo.SHA1();

		for (i = 0; i < 4096; i++)
			sha.update(cryptKey.next());

		for (i = 0; i < cryptSkip; i++)
			sha.update(cryptKey.next());
		cryptShaDigest = sha.digest8();

		for (i = 0; i < 4096; i++)
			sha.update(fillKey.next());

		for (i = 0; i < fillSkip; i++)
			sha.update(fillKey.next());
		fillShaDigest = sha.digest8();

		for (i = 0; i < 4096; i++)
			sha.update(controlKey.next());

		for (i = 0; i < controlSkip; i++)
			sha.update(controlKey.next());
		controlShaDigest = sha.digest8();

		for (i = 0; i < 4096; i++)
			sha.update(prePermutationKey.next());

		for (i = 0; i < prePermutationSkip; i++)
			sha.update(prePermutationKey.next());
		prePermutationShaDigest = sha.digest8();

		for (i = 0; i < 4096; i++)
			sha.update(postPermutationKey.next());

		for (i = 0; i < prePermutationSkip; i++)
			sha.update(postPermutationKey.next());
		postPermutationShaDigest = sha.digest8();
	}

	/**
	 * encrypt buffer. each input byte becomes two bytes, by adding one byte
	 * from fillKey. The byte from controlKey is controlling the order of the
	 * two result bytes:
	 * <p>
	 * <code>if control_byte is even<br> 
	 * then output order is concat(encrypted_data_byte, fill_byte),<br>
	 * else output order is concat(fill_byte, encrypted_data_byte)</code>
	 * <p>
	 * input buffer length must be &gt;= 256 bytes. <br>
	 * prePermutation input buffer inplace. <br>
	 * caller gets back a clear input buffer (full of 0x00).
	 * <p>
	 * output buffer length must be twice the size/length of input buffer.
	 * 
	 * @param inputBuf
	 *            input bytes buffer, length n
	 * @param outputBuf
	 *            output encrypted bytes buffer, must be length 2n
	 * @return returns FALSE if inputs are null or lengths are not correct.
	 *         Else, encrypt data and returns TRUE.
	 */
	public boolean encrypt(byte[] inputBuf, byte[] outputBuf) {
		if (inputBuf == null || outputBuf == null || inputBuf.length < 256
				|| 2 * inputBuf.length != outputBuf.length)
			return false;

		int i, j, k;
		byte temp;

		/**
		 * prePermutation input buffer inplace
		 */
		for (j = 0; j < numCyclesOfPermutations; j++) {
			for (i = 0; i < inputBuf.length; i++) {
				k = 0xff & prePermutationKey.next();
				k = (k << 8) | (0xff & prePermutationKey.next());
				k %= inputBuf.length;
				/**
				 * swap inputBuf(i, k)
				 */
				if (i != k) {
					temp = inputBuf[i];
					inputBuf[i] = inputBuf[k];
					inputBuf[k] = temp;
				}
			}
		}

		/**
		 * encrypt input buffer into output buffer using controlKey to order
		 * each two bytes of encrypted_data and fillKey_data
		 */
		for (i = 0; i < inputBuf.length; i++) {
			byte data = (byte) (inputBuf[i] ^ cryptKey.next());
			byte fill = fillKey.next();
			int control = 0xff & controlKey.next();
			if (control % 2 == 0) {
				outputBuf[i * 2] = data;
				outputBuf[i * 2 + 1] = fill;

			} else {
				outputBuf[i * 2] = fill;
				outputBuf[i * 2 + 1] = data;
			}
		}

		/**
		 * fill inputBuf with low-values
		 */
		java.util.Arrays.fill(inputBuf, 0, inputBuf.length, (byte) 0x00);

		/**
		 * postPermutation output buffer inplace
		 */
		for (j = 0; j < numCyclesOfPermutations; j++) {
			for (i = 0; i < outputBuf.length; i++) {
				k = 0xff & postPermutationKey.next();
				k = (k << 8) | (0xff & postPermutationKey.next());
				k %= outputBuf.length;
				/**
				 * swap outputBuf(i, k)
				 */
				if (i != k) {
					temp = outputBuf[i];
					outputBuf[i] = outputBuf[k];
					outputBuf[k] = temp;
				}
			}
		}

		return true;
	}

	/**
	 * init keys, using hash on prng of each key. Digest message generated from
	 * key xyz is compared with xyzShaDigest variable.
	 * <p>
	 * initDecrypt method is run before decryption starts.
	 * 
	 * @return true if all skip counters are found, and state is ready to
	 *         decrypt cipher data. Else, false.
	 */
	public boolean initDecrypt(byte[] cryptShaDigest, byte[] fillShaDigest,
			byte[] controlShaDigest, byte[] prePermutationShaDigest,
			byte[] postPermutationShaDigest) {
		int i;
		SHA1 sha = new SHA1();
		boolean foundSkip;

		for (i = 0; i < 4096; i++)
			sha.update(cryptKey.next());

		/**
		 * search for cryptSkip between 0 and 0xffff.
		 */
		foundSkip = false;
		for (i = 0; !foundSkip && i < 0xffff; i++) {
			sha.update(cryptKey.next());
			this.cryptShaDigest = ((SHA1) sha.clone()).digest8();
			if (compareBytes(this.cryptShaDigest, cryptShaDigest)) {
				cryptSkip = i; // just for debug
				foundSkip = true;
			}
		}

		if (!foundSkip)
			return false;
		sha.digest8(); // just to reset SHA1

		for (i = 0; i < 4096; i++)
			sha.update(fillKey.next());

		/**
		 * search for fillSkip between 0 and 0xffff.
		 */
		foundSkip = false;
		for (i = 0; !foundSkip && i < 0xffff; i++) {
			sha.update(fillKey.next());
			this.fillShaDigest = ((SHA1) sha.clone()).digest8();
			if (compareBytes(this.fillShaDigest, fillShaDigest)) {
				fillSkip = i; // just for debug
				foundSkip = true;
			}
		}

		if (!foundSkip)
			return false;
		sha.digest8(); // just to reset SHA1

		for (i = 0; i < 4096; i++)
			sha.update(controlKey.next());

		/**
		 * search for controlSkip between 0 and 0xffff.
		 */
		foundSkip = false;
		for (i = 0; !foundSkip && i < 0xffff; i++) {
			sha.update(controlKey.next());
			this.controlShaDigest = ((SHA1) sha.clone()).digest8();
			if (compareBytes(this.controlShaDigest, controlShaDigest)) {
				controlSkip = i; // just for debug
				foundSkip = true;
			}
		}

		if (!foundSkip)
			return false;
		sha.digest8(); // just to reset SHA1

		for (i = 0; i < 4096; i++)
			sha.update(prePermutationKey.next());

		/**
		 * search for prePermutationSkip between 0 and 0xffff.
		 */
		foundSkip = false;
		for (i = 0; !foundSkip && i < 0xffff; i++) {
			sha.update(prePermutationKey.next());
			this.prePermutationShaDigest = ((SHA1) sha.clone()).digest8();
			if (compareBytes(this.prePermutationShaDigest,
					prePermutationShaDigest)) {
				prePermutationSkip = i; // just for debug
				foundSkip = true;
			}
		}

		if (!foundSkip)
			return false;
		sha.digest8(); // just to reset SHA1

		for (i = 0; i < 4096; i++)
			sha.update(postPermutationKey.next());

		/**
		 * search for postPermutationSkip between 0 and 0xffff.
		 */
		foundSkip = false;
		for (i = 0; !foundSkip && i < 0xffff; i++) {
			sha.update(postPermutationKey.next());
			this.postPermutationShaDigest = ((SHA1) sha.clone()).digest8();
			if (compareBytes(this.postPermutationShaDigest,
					postPermutationShaDigest)) {
				postPermutationSkip = i; // just for debug
				foundSkip = true;
			}
		}

		if (!foundSkip)
			return false;

		return true;
	}

	/**
	 * decrypt buffer. Two input bytes become one byte. Determin where is the
	 * ciphred data and the fill byte using rhe control byte.
	 * <p>
	 * <code>if control_byte is even<br> 
	 * then input order is concat(encrypted_data_byte, fill_byte),<br>
	 * else input order is concat(fill_byte, encrypted_data_byte)</code>
	 * <p>
	 * If filler byte is in correctwe o not alert if filler byte
	 * 
	 * @param inputBuf
	 *            input ciphered bytes buffer, length 2n
	 * @param outputBuf
	 *            output data bytes buffer, must be length n
	 * @param len
	 *            intput buffer length
	 * @return returns FALSE if inputs are null or lengths are not correct.
	 *         Else, encrypt data and returns TRUE.
	 */
	public boolean decrypt(byte[] inputBuf, byte[] outputBuf, int len) {
		if (inputBuf == null || outputBuf == null || outputBuf.length < 256
				|| inputBuf.length != 2 * outputBuf.length)
			return false;

		if (garbage) {
			rnd.nextBytes(outputBuf);
			return true;
		}

		int i, j, k;
		byte temp;
		byte[] vectemp = new byte[inputBuf.length * 2 * numCyclesOfPermutations];

		/**
		 * reverse order of postPermutation
		 */
		for (i = 0; i < inputBuf.length * 2 * numCyclesOfPermutations; i++)
			vectemp[i] = postPermutationKey.next();

		for (j = inputBuf.length * 2 * numCyclesOfPermutations - 1; j > -1;) {
			for (i = inputBuf.length - 1; i > -1; i--) {
				k = ((0xff & vectemp[j - 1]) << 8) | (0xff & vectemp[j]);
				k %= inputBuf.length;
				j -= 2;

				/**
				 * swap inputBuf(i, k)
				 */
				if (i != k) {
					temp = inputBuf[i];
					inputBuf[i] = inputBuf[k];
					inputBuf[k] = temp;
				}
			}
		}

		/**
		 * decrypt input buffer into output buffer, using controlKey to discard
		 * the fillKey data
		 */
		for (i = 0; i < len / 2; i++) {
			byte fill = fillKey.next();
			int control = 0xff & controlKey.next();
			if (control % 2 == 0) {
				if (inputBuf[i * 2 + 1] != fill) {
					garbage = true;
					break;
				} else
					outputBuf[i] = (byte) (inputBuf[i * 2] ^ cryptKey.next());
			} else {
				if (inputBuf[i * 2] != fill) {
					garbage = true;
					break;
				} else
					outputBuf[i] = (byte) (inputBuf[i * 2 + 1] ^ cryptKey
							.next());
			}
		}

		if (garbage) {
			rnd.nextBytes(outputBuf);
			return true;
		}

		/**
		 * reverse order of prePermutation
		 */
		for (i = 0; i < outputBuf.length * 2 * numCyclesOfPermutations; i++)
			vectemp[i] = prePermutationKey.next();

		for (j = outputBuf.length * 2 * numCyclesOfPermutations - 1; j > -1;) {
			for (i = outputBuf.length - 1; i > -1; i--) {
				k = ((0xff & vectemp[j - 1]) << 8) | (0xff & vectemp[j]);
				k %= outputBuf.length;
				j -= 2;

				/**
				 * swap outputBuf(i, k)
				 */
				if (i != k) {
					temp = outputBuf[i];
					outputBuf[i] = outputBuf[k];
					outputBuf[k] = temp;
				}
			}
		}

		return true;
	}

	/**
	 * Reset "state" of prng by setting keys to bufkeys and skip each key.
	 *  
	 */
	public void reset() {

		cryptKey = new RC4Key(cryptBuf, 0, null);
		fillKey = new RC4Key(fillBuf, 0, null);
		controlKey = new RC4Key(controlBuf, 0, null);
		prePermutationKey = new RC4Key(prePermutationBuf, 0, null);
		postPermutationKey = new RC4Key(postPermutationBuf, 0, null);

		initEncrypt();
	}

	/**
	 * @return Returns the controlShaDigest.
	 */
	public byte[] getControlShaDigest() {
		return controlShaDigest;
	}

	/**
	 * @return Returns the cryptShaDigest.
	 */
	public byte[] getCryptShaDigest() {
		return cryptShaDigest;
	}

	/**
	 * @return Returns the fillShaDigest.
	 */
	public byte[] getFillShaDigest() {
		return fillShaDigest;
	}

	/**
	 * @return Returns the postPermutationShaDigest.
	 */
	public byte[] getPostPermutationShaDigest() {
		return postPermutationShaDigest;
	}

	/**
	 * @return Returns the prePermutationShaDigest.
	 */
	public byte[] getPrePermutationShaDigest() {
		return prePermutationShaDigest;
	}

	/**
	 * @return Returns the controlBuf.
	 */
	public byte[] getControlBuf() {
		return controlBuf;
	}

	/**
	 * @return Returns the cryptBuf.
	 */
	public byte[] getCryptBuf() {
		return cryptBuf;
	}

	/**
	 * @return Returns the fillBuf.
	 */
	public byte[] getFillBuf() {
		return fillBuf;
	}

	/**
	 * carefull clear of buffers in ZAC5 object
	 *  
	 */
	protected void finalize() throws Throwable {
		super.finalize();
		System.out.println("ZAC5 finalize...");
		/**
		 * clear all keys
		 */
		cryptKey = null;
		fillKey = null;
		controlKey = null;
		prePermutationKey = null;
		postPermutationKey = null;

		/**
		 * clear all keys' buffers
		 */
		java.util.Arrays.fill(cryptBuf, 0, cryptBuf.length, (byte) 0x00);
		java.util.Arrays.fill(fillBuf, 0, fillBuf.length, (byte) 0x00);
		java.util.Arrays.fill(controlBuf, 0, controlBuf.length, (byte) 0x00);
		java.util.Arrays.fill(prePermutationBuf, 0, prePermutationBuf.length,
				(byte) 0x00);
		java.util.Arrays.fill(postPermutationBuf, 0, postPermutationBuf.length,
				(byte) 0x00);
		cryptBuf = null;
		fillBuf = null;
		controlBuf = null;
		prePermutationBuf = null;
		postPermutationBuf = null;

		/**
		 * clear all sha digets' buffers
		 */
		java.util.Arrays.fill(cryptShaDigest, 0, cryptShaDigest.length,
				(byte) 0x00);
		java.util.Arrays.fill(fillShaDigest, 0, fillShaDigest.length,
				(byte) 0x00);
		java.util.Arrays.fill(controlShaDigest, 0, controlShaDigest.length,
				(byte) 0x00);
		java.util.Arrays.fill(prePermutationShaDigest, 0,
				prePermutationShaDigest.length, (byte) 0x00);
		java.util.Arrays.fill(postPermutationShaDigest, 0,
				postPermutationShaDigest.length, (byte) 0x00);
		cryptShaDigest = null;
		fillShaDigest = null;
		controlShaDigest = null;
		prePermutationShaDigest = null;
		postPermutationShaDigest = null;
		rnd = null;
	}

	/**
	 * Run ZAC5 Algorithm. Copyright (c) 2005 Zur Aougav <aougav@hotmail.com>
	 * <p>
	 * Command line syntax:
	 * <p>
	 * java ZAC5 [options] [ops] [inputfilename outputfilename]
	 * <p>
	 * options: <br>
	 * -crf &lt;cryptKeyFile.key&gt;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
	 * default: cryptKeyFile.key <br>
	 * -fif &lt;fillKeyFile.key&gt;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
	 * default: fillKeyFile.key <br>
	 * -cof &lt;controlKeyFile.key&gt;&nbsp;&nbsp;&nbsp;&nbsp; default:
	 * controlKeyFile.key <br>
	 * -prf &lt;prePermutationKeyFile.key&gt;&nbsp;&nbsp;&nbsp;&nbsp; default:
	 * prePermutationKeyFile.key <br>
	 * -pof &lt;postPermutationKeyFile.key&gt;&nbsp;&nbsp;&nbsp;&nbsp; default:
	 * postPermutationKeyFile.key <br>
	 * <p>
	 * ops: <br>
	 * -h&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; print this help message <br>
	 * -e&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; encrypt inputfilename into
	 * outputfilename <br>
	 * -enc&nbsp;&nbsp;&nbsp;&nbsp; encrypt inputfilename into outputfilename
	 * <br>
	 * -d&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; decrypt inputfilename into
	 * outputfilename <br>
	 * -dec&nbsp;&nbsp;&nbsp;&nbsp; decrypt inputfilename into outputfilename
	 * <br>
	 * -compare&nbsp;&nbsp;&nbsp;&nbsp; compare two files - inputfilename and
	 * outputfilename <br>
	 * -gen&nbsp;&nbsp;&nbsp;&nbsp; generate random keys and write them to key
	 * files <br>
	 * 
	 * @param args
	 *            keys, operations, input and output filenames
	 * @throws Exception
	 *             missing operands or IOExceptions
	 */
	public static void main(String[] args) throws Exception {
		String cryptKeyFile = "cryptKeyFile.key"; // -crf
		String fillKeyFile = "fillKeyFile.key"; // -fif
		String controlKeyFile = "controlKeyFile.key"; // -cof
		String prePermutationKeyFile = "prePermutationKeyFile.key"; // -prf
		String postPermutationKeyFile = "postPermutationKeyFile.key"; // -pof
		String op = null; // -e / -enc / -d / -dec / -gen
		String inFilename = "";
		String outFilename = "";
		int i = 0;

		System.out
				.println("ZAC5 Algorithm. Copyright (c) 2005 Zur Aougav <aougav@hotmail.com>\nJRandTest <http://jrandtest.sourceforge.net>");

		if (args == null || args.length == 0 || args[0] == null
				|| args[0].equals("-?") || args[0].equals("-h")
				|| args[0].equals("-help")) {
			System.out
					.println("java ZAC5 [options] [ops] [inputfilename outputfilename]");
			System.out.println("options:");
			System.out
					.println(" -crf <cryptKeyFile.key>     default: cryptKeyFile.key");
			System.out
					.println(" -fif <fillKeyFile.key>      default: fillKeyFile.key");
			System.out
					.println(" -cof <controlKeyFile.key>   default: controlKeyFile.key");
			System.out
					.println(" -prf <prePermutationKeyFile.key>   default: prePermutationKeyFile.key");
			System.out
					.println(" -pof <postPermutationKeyFile.key>   default: postPermutationKeyFile.key");
			System.out.println("ops:");
			System.out
					.println(" -e              encrypt inputfilename into outputfilename");
			System.out
					.println(" -enc            encrypt inputfilename into outputfilename");
			System.out
					.println(" -d              decrypt inputfilename into outputfilename");
			System.out
					.println(" -dec            decrypt inputfilename into outputfilename");
			System.out
					.println(" -compare        compare two files - inputfilename and outputfilename");
			System.out
					.println(" -gen            generate random keys and write them to key files");
			return;
		}

		for (; i < args.length; i++) {
			if (args[i].equals("-crf")) {
				if (i + 1 >= args.length)
					throw new Exception("missing cryptKeyFile name");
				else
					cryptKeyFile = args[++i];
				continue;
			}

			if (args[i].equals("-fif")) {
				if (i + 1 >= args.length)
					throw new Exception("missing fillKeyFile name");
				else
					fillKeyFile = args[++i];
				continue;
			}

			if (args[i].equals("-cof")) {
				if (i + 1 >= args.length)
					throw new Exception("missing controlKeyFile name");
				else
					controlKeyFile = args[++i];
				continue;
			}

			if (args[i].equals("-prf")) {
				if (i + 1 >= args.length)
					throw new Exception("missing prePermutationKeyFile name");
				else
					prePermutationKeyFile = args[++i];
				continue;
			}

			if (args[i].equals("-pof")) {
				if (i + 1 >= args.length)
					throw new Exception("missing postPermutationKeyFile name");
				else
					postPermutationKeyFile = args[++i];
				continue;
			}

			if (op == null && (args[i].equals("-e") || args[i].equals("-enc"))) {
				op = args[i];
				continue;
			}

			if (op == null && (args[i].equals("-d") || args[i].equals("-dec"))) {
				op = args[i];
				continue;
			}

			if (op == null && args[i].equals("-gen")) {
				op = args[i];
				continue;
			}

			if (op == null && args[i].equals("-compare")) {
				op = args[i];
				continue;
			}

			if (i + 1 >= args.length)
				throw new Exception("missing outputfilename");
			inFilename = args[i];
			outFilename = args[++i];
		}

		/**
		 * gen key files
		 */
		if (op.equals("-gen")) {
			byte[] key = new byte[256];
			java.util.Random rnd = new java.util.Random();
			java.io.FileOutputStream fos = null;

			try {

				System.out.println("Generate key files...");

				System.out.println("Generate random data in " + cryptKeyFile);
				rnd.nextBytes(key);
				fos = new java.io.FileOutputStream(cryptKeyFile);
				fos.write(key);
				fos.close();

				System.out.println("Generate random data in " + fillKeyFile);
				rnd.nextBytes(key);
				fos = new java.io.FileOutputStream(fillKeyFile);
				fos.write(key);
				fos.close();

				System.out.println("Generate random data in " + controlKeyFile);
				rnd.nextBytes(key);
				fos = new java.io.FileOutputStream(controlKeyFile);
				fos.write(key);
				fos.close();

				System.out.println("Generate random data in "
						+ prePermutationKeyFile);
				rnd.nextBytes(key);
				fos = new java.io.FileOutputStream(prePermutationKeyFile);
				fos.write(key);
				fos.close();

				System.out.println("Generate random data in "
						+ postPermutationKeyFile);
				rnd.nextBytes(key);
				fos = new java.io.FileOutputStream(postPermutationKeyFile);
				fos.write(key);
				fos.close();
			} catch (Exception e) {
				System.out.println("Error: " + e);
			}

			return;
		}

		/**
		 * encrypt file
		 */
		if (op.equals("-e") || op.equals("-enc")) {
			byte[] cryptKey = new byte[256];
			byte[] fillKey = new byte[256];
			byte[] controlKey = new byte[256];
			byte[] prePermutationKey = new byte[256];
			byte[] postPermutationKey = new byte[256];
			java.io.FileOutputStream fos = null;
			java.io.FileInputStream fis = null;

			try {

				System.out.println("Crypt file " + inFilename + " into "
						+ outFilename);

				System.out.println("Read " + cryptKeyFile);
				fis = new java.io.FileInputStream(cryptKeyFile);
				fis.read(cryptKey);
				fis.close();

				System.out.println("Read " + fillKeyFile);
				fis = new java.io.FileInputStream(fillKeyFile);
				fis.read(fillKey);
				fis.close();

				System.out.println("Read " + controlKeyFile);
				fis = new java.io.FileInputStream(controlKeyFile);
				fis.read(controlKey);
				fis.close();

				System.out.println("Read " + prePermutationKeyFile);
				fis = new java.io.FileInputStream(prePermutationKeyFile);
				fis.read(prePermutationKey);
				fis.close();

				System.out.println("Read " + postPermutationKeyFile);
				fis = new java.io.FileInputStream(postPermutationKeyFile);
				fis.read(postPermutationKey);
				fis.close();

				System.out.println("Open input file " + inFilename);
				fis = new java.io.FileInputStream(inFilename);

				System.out.println("Open output file " + outFilename);
				fos = new java.io.FileOutputStream(outFilename);

				/**
				 * write 8 bytes of the length of input file
				 */
				long avail = (new java.io.File(inFilename)).length();
				System.out.println("avail=" + avail);
				byte[] vectemp = new byte[8];
				i = 0;
				for (int j = 56; j >= 0; j -= 8)
					vectemp[i++] = (byte) (avail >>> j);
				fos.write(vectemp);

				ZAC5 algo = new ZAC5(cryptKey, fillKey, controlKey,
						prePermutationKey, postPermutationKey);
				algo.initEncrypt();
				fos.write(algo.getCryptShaDigest());
				fos.write(algo.getFillShaDigest());
				fos.write(algo.getControlShaDigest());
				fos.write(algo.getPrePermutationShaDigest());
				fos.write(algo.getPostPermutationShaDigest());

				byte[] buffer = new byte[256];
				byte[] outbuffer = new byte[256 * 2];
				int len;

				while ((len = fis.read(buffer)) > -1) {
					algo.encrypt(buffer, outbuffer);
					fos.write(outbuffer);
				}

				fis.close();
				fos.close();

			} catch (Exception e) {
				//System.out.println("Error: " + e);
				e.printStackTrace();
			}

			return;
		}

		/**
		 * decrypt file
		 */
		if (op.equals("-d") || op.equals("-dec")) {
			byte[] cryptKey = new byte[256];
			byte[] fillKey = new byte[256];
			byte[] controlKey = new byte[256];
			byte[] prePermutationKey = new byte[256];
			byte[] postPermutationKey = new byte[256];
			byte[] cryptShaDigest = new byte[20];
			byte[] fillShaDigest = new byte[20];
			byte[] controlShaDigest = new byte[20];
			byte[] prePermutationShaDigest = new byte[20];
			byte[] postPermutationShaDigest = new byte[20];
			java.io.FileOutputStream fos = null;
			java.io.FileInputStream fis = null;

			try {

				System.out.println("Decrypt file " + inFilename + " into "
						+ outFilename);

				System.out.println("Read " + cryptKeyFile);
				fis = new java.io.FileInputStream(cryptKeyFile);
				fis.read(cryptKey);
				fis.close();

				System.out.println("Read " + fillKeyFile);
				fis = new java.io.FileInputStream(fillKeyFile);
				fis.read(fillKey);
				fis.close();

				System.out.println("Read " + controlKeyFile);
				fis = new java.io.FileInputStream(controlKeyFile);
				fis.read(controlKey);
				fis.close();

				System.out.println("Read " + prePermutationKeyFile);
				fis = new java.io.FileInputStream(prePermutationKeyFile);
				fis.read(prePermutationKey);
				fis.close();

				System.out.println("Read " + postPermutationKeyFile);
				fis = new java.io.FileInputStream(postPermutationKeyFile);
				fis.read(postPermutationKey);
				fis.close();

				System.out.println("Open input file " + inFilename);
				fis = new java.io.FileInputStream(inFilename);

				System.out.println("Open output file " + outFilename);
				fos = new java.io.FileOutputStream(outFilename);

				/**
				 * write 8 bytes of the length of input file
				 */
				long avail = 0;
				byte[] vectemp = new byte[8];
				fis.read(vectemp);
				for (i = 0; i < 8; i++)
					avail = (avail << 8) | (0xffL & vectemp[i]);
				System.out.println("avail=" + avail);

				fis.read(cryptShaDigest);
				fis.read(fillShaDigest);
				fis.read(controlShaDigest);
				fis.read(prePermutationShaDigest);
				fis.read(postPermutationShaDigest);

				ZAC5 algo = new ZAC5(cryptKey, fillKey, controlKey,
						prePermutationKey, postPermutationKey);

				if (!algo.initDecrypt(cryptShaDigest, fillShaDigest,
						controlShaDigest, prePermutationShaDigest,
						postPermutationShaDigest)) {
					System.out.println("Invalid data files.");
					return;
				}

				byte[] inbuffer = new byte[256 * 2];
				byte[] outbuffer = new byte[256];
				int len;

				while (avail > 0 && (len = fis.read(inbuffer)) > -1) {
					algo.decrypt(inbuffer, outbuffer, len);
					if (avail < outbuffer.length) {
						fos.write(outbuffer, 0, (int) avail);
						avail = 0;
					} else {
						fos.write(outbuffer, 0, len / 2);
						avail -= len / 2;
					}
				}

				fis.close();
				fos.close();

			} catch (Exception e) {
				e.printStackTrace();
			}

			return;
		}

		/**
		 * compare infile and outfile
		 */
		if (op.equals("-compare")) {
			java.io.FileInputStream fis1 = null;
			java.io.FileInputStream fis2 = null;

			try {

				System.out.println("Compare file " + inFilename + " with "
						+ outFilename);

				System.out.println("Open input file1 " + inFilename);
				fis1 = new java.io.FileInputStream(inFilename);

				System.out.println("Open input file2 " + outFilename);
				fis2 = new java.io.FileInputStream(outFilename);

				byte[] buffer1 = new byte[4096];
				byte[] buffer2 = new byte[4096];
				int len1;
				int len2;
				boolean eq = true;

				do {
					len1 = fis1.read(buffer1);

					len2 = fis2.read(buffer2);

					if ((len1 == -1 && len2 != -1)
							|| (len1 != -1 && len2 == -1) || len1 != len2)
						eq = false;
					else
						for (i = 0; eq && i < len1; i++)
							if (buffer1[i] != buffer2[i])
								eq = false;
				} while (len1 > -1 && len2 > -1 && eq);

				fis1.close();
				fis2.close();

				if (eq)
					System.out.println("Files are equal.");
				else
					System.out.println("Files are not equal.");
			} catch (Exception e) {
				e.printStackTrace();
			}

			return;
		}

		System.out.println("Unkown operation " + op + " or not yet supported.");
	}

}