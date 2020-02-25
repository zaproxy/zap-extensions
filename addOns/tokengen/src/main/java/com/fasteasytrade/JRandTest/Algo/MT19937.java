/*
 * Created on 16/02/2005
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

import com.fasteasytrade.JRandTest.IO.FileAlgoRandomStream;

/**
 * Stream of random bytes from MT19937Prng class
 * <P>
 * 
 * @author Zur Aougav
 */
public class MT19937 extends FileAlgoRandomStream {

	MT19937Prng mt = null; // actual class algorithm

	long[] defaultPublicKey = { 0x123, 0x234, 0x345, 0x456 };

	byte[] outAlgoBuffer = new byte[4];
	
	int outAlgoBufferIx = outAlgoBuffer.length;
	
	public MT19937() {
		super();
	}

	public MT19937(String keyFileName) {
		super(keyFileName);
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#getFilename()
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#setFilename(java.lang.String)
	 */
	public void setFilename(String s) {
		filename = s;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.AlgoRandomStream#setupKeys()
	 */
	public void setupKeys() {
		publicKeyLength = 256;
		privateKeyLength = 256;
		super.setupKeys();
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.AlgoRandomStream#setup()
	 */
	public void setup() {
		mt = new MT19937Prng();

		if (publicKey == null || publicKey.length < 4)
			mt.init_by_array(defaultPublicKey, defaultPublicKey.length);
		else {
			long[] p = new long[publicKey.length / 4];
			for (int i = 0; i < p.length; i++) {
				p[i] = 0xff & publicKey[4 * i];
				p[i] = (p[i] << 8) | (0xff & publicKey[4 * i + 1]);
				p[i] = (p[i] << 8) | (0xff & publicKey[4 * i + 2]);
				p[i] = (p[i] << 8) | (0xff & publicKey[4 * i + 3]);
			}
			mt.init_by_array(p, p.length);
		}
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#openInputStream()
	 *      <p>
	 *      if filename exists (not null), we open file and later will encrypt
	 *      it. Else, algorithm will generate random data (as PRNG).
	 */
	public boolean openInputStream() throws Exception {
		
		setup(); // make sure algorithm and keys/states are reset
		
		if (filename != null)
			super.openInputStream();

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
			int i = (int) mt.genrand_int32();
			outAlgoBuffer[0] = (byte) (i >>> 24);
			outAlgoBuffer[1] = (byte) (i >>> 16);
			outAlgoBuffer[2] = (byte) (i >>> 8);
			outAlgoBuffer[3] = (byte) i;
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

		int prng = 0;

		if (outAlgoBufferIx == outAlgoBuffer.length) {
			prng = (int) mt.genrand_int32();
			if (filename == null)
				count += 4;
		} else {
			byte temp;
			for (int i = 0; i < 4; i++) {
				temp = readByte();
				prng = (prng << 8) | (0xff & temp);
			}
		}
		if (filename == null)
			return prng;

		/*
		 * we have a real filename to encrypt
		 */
		int data = super.readInt();
		return data ^ prng;
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

		long prng = 0;

		if (outAlgoBufferIx == outAlgoBuffer.length) {
			prng = 0xffffffffL & mt.genrand_int32();
			prng = (prng << 32) | (0xffffffffL & mt.genrand_int32());
			if (filename == null)
				count += 8;
		} else {
			byte temp;
			for (int i = 0; i < 8; i++) {
				temp = readByte();
				prng = (prng << 8) | (0xff & temp);
			}
		}
		if (filename == null)
			return prng;

		/*
		 * we have a real filename to encrypt
		 */
		long data = super.readLong();
		return data ^ prng;
	}

}