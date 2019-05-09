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
 * Stream of random bytes from BFcipher class
 * <P>
 * 
 * @author Zur Aougav
 */
public class BlowFish extends FileAlgoRandomStream {

	/**
	 * actual class algorithm 
	 */
	BFcipher bf = null;

	/**
	 * default key
	 */
	byte[] defaultPublicKey = { 0x1, 0x2, 0x3, 0x5 };

	/**
	 * input buffer to algorithm. Always full of 0x00's.
	 */
	byte[] inAlgoBuffer = new byte[256];
	
	/**
	 * output buffer to algorithm. CBC fill it with different values.
	 */
	
	byte[] outAlgoBuffer = new byte[256];
	
	int outAlgoBufferIx = outAlgoBuffer.length;

	/**
	 * iv array to algorthm
	 */
	byte[] iv = { (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98,
			(byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10 };
	
	public BlowFish() {
		super();
	}

	public BlowFish(String keyFileName) {
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

		try {
			if (publicKey == null)
				bf = new BFcipher(defaultPublicKey, iv);
			else
				bf = new BFcipher(publicKey, iv);
			return;
		} catch (Exception e) {
			System.out.println(e);
		}

		/*
		 * if still we can not init BlowFish...
		 */
		if (bf == null)
			try {
				bf = new BFcipher(publicKey, iv);
			} catch (Exception e) {
				System.out.println(e);
			}
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#openInputStream()
	 *      <p>
	 *      if filename exists (not null), we open file and later will encrypt
	 *      it. Else, algorithm will generate random data (as PRNG).
	 */
	public boolean openInputStream() throws Exception {
		
		setup(); // just to be sure to reset all blowfish states
		
		if (bf == null)
			return false;
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

		byte prng = -1;

		/*
		 * encrypt file if exists
		 */
		if (filename != null) {
			if (countLastRead == actualSize) { // end of buffer?
				super.readByte(); // read & fill buffer from file
				if (!isOpen())
					return -1;
				countLastRead = 0;
				bf.EncryptBlock(buffer, buffer); // encrypt it
			}

			prng = buffer[countLastRead++];
			count++;
			return prng;
		}

		/*
		 * we have no real filename to encrypt
		 */
		if (outAlgoBufferIx == outAlgoBuffer.length) {
			/*
			 * inAlgoBuffer is always full of 0x00's
			 */
			bf.EncryptBlock(inAlgoBuffer, outAlgoBuffer);
			outAlgoBufferIx = 0; 
		}

		prng = outAlgoBuffer[outAlgoBufferIx++];
		count++;
		return prng;
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
		for (int i = 0; i < 4; i++)
			prng = (prng << 8) | (0xff & readByte());

		if (filename == null)
			return prng;

		/*
		 * we have a real filename to encrypt
		 */
		int data = super.readInt();
		return (byte) (prng ^ data);
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
		for (int i = 0; i < 8; i++)
			prng = (prng << 8) | (0xffL & readByte());

		if (filename == null)
			return prng;

		/*
		 * we have a real filename to encrypt
		 */
		long data = super.readLong();
		return (byte) (prng ^ data);
	}

}