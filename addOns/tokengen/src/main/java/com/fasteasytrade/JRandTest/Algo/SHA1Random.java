/*
 * Created on 08/04/2005
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

import com.fasteasytrade.JRandTest.IO.*;

/**
 * SHA1 algorithm as a random stream based on SHA1 message digest class.
 * <p>
 * Implementation is based on SHA1 algorithm in NIST test package.
 * <p>
 * 
 * @author Zur Aougav
 */
public class SHA1Random extends FileAlgoRandomStream {

	SHA1 algo = null;

	/**
	 * outAlgoBuffer is filled with key array, the first time. The buffer is
	 * used as an input and output to SHA1.
	 */
	byte[] outAlgoBuffer = new byte[20];

	int outAlgoBufferIx = outAlgoBuffer.length;

	/**
	 * random IV to SHA1 class
	 */
	byte[] iv = new byte[20];

	/**
	 * random Key to SHA1 class. Used as the first update input buffer to SHA1
	 * (key is copied into outAlgoBuffer).
	 */
	byte[] key = new byte[20];

	public SHA1Random() {
		super();
	}

	public SHA1Random(String keyFileName) {
		super(keyFileName);
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.AlgoRandomStream#setupKeys()
	 */
	public void setupKeys() {

		super.setupKeys();

	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.AlgoRandomStream#setup()
	 *      <p>
	 *      makes only once a new SHA1 object and an IV vector.
	 */
	public void setup() {

		/**
		 * makes only once a new SHA1 object and an IV vector.
		 */
		if (algo == null) {
			algo = new SHA1();
			java.util.Random rnd = new java.util.Random(new java.util.Date()
					.getTime());
			rnd.nextBytes(iv);
			rnd.nextBytes(key);
		}
		/**
		 * First time, the key array is the input to SHA1, so we copy it into
		 * outAlgoBuffer (which is used as input and outut buffer to SHA1).
		 */
		System.arraycopy(key, 0, outAlgoBuffer, 0, outAlgoBuffer.length);

	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#openInputStream()
	 *      <p>
	 *      if filename exists (not null), we open file and later will encrypt
	 *      it. Else, algorithm will generate random data (as PRNG).
	 */
	public boolean openInputStream() throws Exception {

		if (filename != null)
			super.openInputStream();

		setup(); // make sure algorithm and keys/states are reset
		count = 0;
		countLastRead = SIZE;
		actualSize = SIZE;
		outAlgoBufferIx = outAlgoBuffer.length;
		open = true;
		return open;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#readByte()
	 */
	public byte readByte() throws Exception {
		if (!isOpen())
			return -1;

		if (filename == null && count > maxCount) {
			open = false;
			return -1;
		}

		if (outAlgoBufferIx == outAlgoBuffer.length) {
			algo.init(iv);
			/**
			 * update SHA1 using outAlgoBuffer array (20 bytes = 160 bits) 4
			 * times, so update with 80 bytes ( > 64 bytes = 512 bits!)
			 */
			for (int k = 0; k < 4; k++)
				algo.update(outAlgoBuffer);
			/**
			 * gets H internal vector from SHA1 as output buffer (and as input
			 * to next update iteration).
			 */
			algo.getHAsBytes(outAlgoBuffer);
			outAlgoBufferIx = 0;
		}

		byte prng = outAlgoBuffer[outAlgoBufferIx++];

		if (filename == null) {
			count++;
			return prng;
		}

		/*
		 * we have a real filename to encrypt
		 */
		byte data = super.readByte();
		return (byte) (prng ^ data);
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#readInt()
	 */
	public int readInt() throws Exception {
		if (!isOpen())
			return -1;

		if (filename == null && count > maxCount) {
			open = false;
			return -1;
		}

		int prng = 0xff & readByte();
		prng = (prng << 8) | (0xff & readByte());
		prng = (prng << 8) | (0xff & readByte());
		prng = (prng << 8) | (0xff & readByte());

		return prng;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#readLong()
	 */
	public long readLong() throws Exception {
		if (!isOpen())
			return -1;

		if (filename == null && count > maxCount) {
			open = false;
			return -1;
		}

		long prng = 0xff & readByte();
		for (int i = 0; i < 7; i++)
			prng = (prng << 8) | (0xff & readByte());

		return prng;
	}

	public static void main(String[] args) {
		if (args != null && args.length > 0 && args[0] != null) {
			SHA1Random algo = new SHA1Random();
			algo.setup();
			try {
				algo.openInputStream();
				byte temp;
				for (int i = 0; i < 100; i++) {
					System.out.print(algo.readByte());
					System.out.print(",");
				}
				System.out.println();
			} catch (Exception e) {
				System.out.println("" + e);
			}
		}
	}
}