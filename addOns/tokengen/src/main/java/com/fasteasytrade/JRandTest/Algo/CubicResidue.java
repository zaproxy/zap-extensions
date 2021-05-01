/*
 * Created on 02/04/2005
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
 * CubicResidue Prng algorithm from NIST test package
 * <p>
 * Use CubicResiduePrng class.
 * 
 * @author Zur Aougav
 */
public class CubicResidue extends FileAlgoRandomStream {

	CubicResiduePrng algo = null;

	byte[] outAlgoBuffer = new byte[8];

	int outAlgoBufferIx = outAlgoBuffer.length;

	public CubicResidue() {
		super();
	}

	public CubicResidue(String keyFileName) {
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
	 */
	public void setup() {
		
		/**
		 * construct CubicResiduePrng only once! 
		 */
		if (algo == null)
			algo = new CubicResiduePrng();
		else
			algo.reset(); // restore g to g0

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
			// take 64 bits
			long l = algo.nextLong();
			
			outAlgoBufferIx = 0;
			for (int i = 64 - 8; i >= 0; i -= 8)
				outAlgoBuffer[outAlgoBufferIx++] = (byte) (l >> i);

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
			CubicResidue algo = new CubicResidue();
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