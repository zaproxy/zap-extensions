/*
 * Created on 17/02/2005
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

import java.io.*;

/**
 * Alleged RC4 implemented as RC4Key. Returns byte.
 * <p>
 * Include debug level and logging into external file.
 * 
 * @author Zur Aougav
 *  
 */
public class RC4Key extends Cipher {

	boolean ready = false; // is the algorithm is ready?

	private byte[] Key; // original key

	private byte[] KeyBytes = new byte[256];

	private byte[] CypherBytes = new byte[256];

	int i, jump;

	PrintStream ps = null; // used by the log

	int debugLevel = 0; // write to log : 0=none, 1=stream, 2=full dscription

	/**
	 * @param Key
	 *            is a byte array to init internal state vector.
	 * @param d
	 *            for debug level. 0 is none. 1 is minimal into logfile. 2 is
	 *            detailed.
	 * @param logname
	 *            is used with d > 0
	 */
	RC4Key(byte[] Key, int d, String logname) {
		debugLevel = d;
		try {
			if (debugLevel > 0)
				ps = new PrintStream(new FileOutputStream(getClass().getName()
						+ logname + ".log"));
		} catch (Exception e) {
			System.out.println(e);
			ps = null;
		}
		if (Key.length == 0)
			return;
		this.Key = Key;
		for (i = 0; i < 256; ++i)
			KeyBytes[i] = Key[i % Key.length];

		for (i = 0; i < 256; ++i)
			CypherBytes[i] = (byte) i;

		jump = 0;
		byte temp;
		for (i = 0; i < 256; ++i) {
			jump = (0xFF & jump + 0xFF & CypherBytes[i] + 0xFF & KeyBytes[i]) & 0xFF;
			temp = CypherBytes[i];
			CypherBytes[i] = CypherBytes[jump];
			CypherBytes[jump] = temp;
		}

		i = 0;
		jump = 0;
		ready = true;
	}

	/**
	 * encrypt/decrypt from data to Result. Uses the key in Key
	 */
	public byte next() {
		if (!ready)
			return (byte) 0x00;

		i = (i + 1) % 256;
		if (debugLevel == 2) {
			print("i=" + i + ", j=" + jump + " +c[" + i + "]=");
			print(CypherBytes[i]);
		}
		jump = ((0xFF & jump) + (0xFF & CypherBytes[i])) & 0xff; // % 256;
		if (debugLevel == 2) {
			print(", new j=" + jump + ", c[j]=");
			print(CypherBytes[jump]);
			print(", c[i]=");
			print(CypherBytes[i]);
			print(" + c[j]=");
			print(CypherBytes[jump]);
		}
		int T = ((0xFF & CypherBytes[i]) + (0xFF & CypherBytes[jump])) & 0xff;

		if (debugLevel == 2) {
			print(" ==> T=" + T);
		}

		byte temp = CypherBytes[i];
		CypherBytes[i] = CypherBytes[jump];
		CypherBytes[jump] = temp;
		if (debugLevel == 2) {
			print(" returns c[t]=");
			println(CypherBytes[T]);
		}
		if (debugLevel == 1 && ps != null)
			ps.print(CypherBytes[T]);
		return CypherBytes[T];
	}

	public void print(String s) {
		if (ps == null)
			return;
		ps.print(s);
	}

	public void println(String s) {
		if (ps == null)
			return;
		ps.println(s);
	}

	public void print(byte s) {
		if (ps == null)
			return;
		ps.print(0xff & s);
	}

	public void println(byte s) {
		if (ps == null)
			return;
		ps.println(0xff & s);
	}

	/**
	 * carefull clear of buffers in RC4Key object
	 *  
	 */
	protected void finalize() throws Throwable {
		super.finalize();		
		System.out.println("RC4Key finalize...");
		if (Key != null)
			java.util.Arrays.fill(Key, 0, Key.length, (byte) 0x00);
		java.util.Arrays.fill(KeyBytes, 0, KeyBytes.length, (byte) 0x00);
		java.util.Arrays.fill(CypherBytes, 0, CypherBytes.length, (byte) 0x00);

		Key = null;
		KeyBytes = null;
		CypherBytes = null;

	}
}