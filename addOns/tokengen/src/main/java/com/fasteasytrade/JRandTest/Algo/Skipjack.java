/*
 * Created on 17/04/2005
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

/**
 * Skipjack algorithm copyright (c) 2005 Zur Aougav.
 * <p>
 * Hand translation to java from C implementation.
 * <p>
 * Originally written by Panu Rissanen <bande@lut.fi>1998.06.24 <br>
 * optimized by Mark Tillotson <markt@chaos.org.uk>1998.06.25 <br>
 * optimized by Paulo Barreto <pbarreto@nw.com.br>1998.06.30 <br>
 * gnupg support by Werner Koch <dd9jn@amsat.org>1998.07.02 <br>
 * 
 * @author Zur Aougav
 *  
 */

public class Skipjack extends Cipher {

	boolean initialized = false;

	byte[][] tab = new byte[10][256];

	/**
	 * The F-table byte permutation (see description of the G-box permutation)
	 */
	static final byte[] fTable = { (byte) 0xa3, (byte) 0xd7, (byte) 0x09,
			(byte) 0x83, (byte) 0xf8, (byte) 0x48, (byte) 0xf6, (byte) 0xf4,
			(byte) 0xb3, (byte) 0x21, (byte) 0x15, (byte) 0x78, (byte) 0x99,
			(byte) 0xb1, (byte) 0xaf, (byte) 0xf9, (byte) 0xe7, (byte) 0x2d,
			(byte) 0x4d, (byte) 0x8a, (byte) 0xce, (byte) 0x4c, (byte) 0xca,
			(byte) 0x2e, (byte) 0x52, (byte) 0x95, (byte) 0xd9, (byte) 0x1e,
			(byte) 0x4e, (byte) 0x38, (byte) 0x44, (byte) 0x28, (byte) 0x0a,
			(byte) 0xdf, (byte) 0x02, (byte) 0xa0, (byte) 0x17, (byte) 0xf1,
			(byte) 0x60, (byte) 0x68, (byte) 0x12, (byte) 0xb7, (byte) 0x7a,
			(byte) 0xc3, (byte) 0xe9, (byte) 0xfa, (byte) 0x3d, (byte) 0x53,
			(byte) 0x96, (byte) 0x84, (byte) 0x6b, (byte) 0xba, (byte) 0xf2,
			(byte) 0x63, (byte) 0x9a, (byte) 0x19, (byte) 0x7c, (byte) 0xae,
			(byte) 0xe5, (byte) 0xf5, (byte) 0xf7, (byte) 0x16, (byte) 0x6a,
			(byte) 0xa2, (byte) 0x39, (byte) 0xb6, (byte) 0x7b, (byte) 0x0f,
			(byte) 0xc1, (byte) 0x93, (byte) 0x81, (byte) 0x1b, (byte) 0xee,
			(byte) 0xb4, (byte) 0x1a, (byte) 0xea, (byte) 0xd0, (byte) 0x91,
			(byte) 0x2f, (byte) 0xb8, (byte) 0x55, (byte) 0xb9, (byte) 0xda,
			(byte) 0x85, (byte) 0x3f, (byte) 0x41, (byte) 0xbf, (byte) 0xe0,
			(byte) 0x5a, (byte) 0x58, (byte) 0x80, (byte) 0x5f, (byte) 0x66,
			(byte) 0x0b, (byte) 0xd8, (byte) 0x90, (byte) 0x35, (byte) 0xd5,
			(byte) 0xc0, (byte) 0xa7, (byte) 0x33, (byte) 0x06, (byte) 0x65,
			(byte) 0x69, (byte) 0x45, (byte) 0x00, (byte) 0x94, (byte) 0x56,
			(byte) 0x6d, (byte) 0x98, (byte) 0x9b, (byte) 0x76, (byte) 0x97,
			(byte) 0xfc, (byte) 0xb2, (byte) 0xc2, (byte) 0xb0, (byte) 0xfe,
			(byte) 0xdb, (byte) 0x20, (byte) 0xe1, (byte) 0xeb, (byte) 0xd6,
			(byte) 0xe4, (byte) 0xdd, (byte) 0x47, (byte) 0x4a, (byte) 0x1d,
			(byte) 0x42, (byte) 0xed, (byte) 0x9e, (byte) 0x6e, (byte) 0x49,
			(byte) 0x3c, (byte) 0xcd, (byte) 0x43, (byte) 0x27, (byte) 0xd2,
			(byte) 0x07, (byte) 0xd4, (byte) 0xde, (byte) 0xc7, (byte) 0x67,
			(byte) 0x18, (byte) 0x89, (byte) 0xcb, (byte) 0x30, (byte) 0x1f,
			(byte) 0x8d, (byte) 0xc6, (byte) 0x8f, (byte) 0xaa, (byte) 0xc8,
			(byte) 0x74, (byte) 0xdc, (byte) 0xc9, (byte) 0x5d, (byte) 0x5c,
			(byte) 0x31, (byte) 0xa4, (byte) 0x70, (byte) 0x88, (byte) 0x61,
			(byte) 0x2c, (byte) 0x9f, (byte) 0x0d, (byte) 0x2b, (byte) 0x87,
			(byte) 0x50, (byte) 0x82, (byte) 0x54, (byte) 0x64, (byte) 0x26,
			(byte) 0x7d, (byte) 0x03, (byte) 0x40, (byte) 0x34, (byte) 0x4b,
			(byte) 0x1c, (byte) 0x73, (byte) 0xd1, (byte) 0xc4, (byte) 0xfd,
			(byte) 0x3b, (byte) 0xcc, (byte) 0xfb, (byte) 0x7f, (byte) 0xab,
			(byte) 0xe6, (byte) 0x3e, (byte) 0x5b, (byte) 0xa5, (byte) 0xad,
			(byte) 0x04, (byte) 0x23, (byte) 0x9c, (byte) 0x14, (byte) 0x51,
			(byte) 0x22, (byte) 0xf0, (byte) 0x29, (byte) 0x79, (byte) 0x71,
			(byte) 0x7e, (byte) 0xff, (byte) 0x8c, (byte) 0x0e, (byte) 0xe2,
			(byte) 0x0c, (byte) 0xef, (byte) 0xbc, (byte) 0x72, (byte) 0x75,
			(byte) 0x6f, (byte) 0x37, (byte) 0xa1, (byte) 0xec, (byte) 0xd3,
			(byte) 0x8e, (byte) 0x62, (byte) 0x8b, (byte) 0x86, (byte) 0x10,
			(byte) 0xe8, (byte) 0x08, (byte) 0x77, (byte) 0x11, (byte) 0xbe,
			(byte) 0x92, (byte) 0x4f, (byte) 0x24, (byte) 0xc5, (byte) 0x32,
			(byte) 0x36, (byte) 0x9d, (byte) 0xcf, (byte) 0xf3, (byte) 0xa6,
			(byte) 0xbb, (byte) 0xac, (byte) 0x5e, (byte) 0x6c, (byte) 0xa9,
			(byte) 0x13, (byte) 0x57, (byte) 0x25, (byte) 0xb5, (byte) 0xe3,
			(byte) 0xbd, (byte) 0xa8, (byte) 0x3a, (byte) 0x01, (byte) 0x05,
			(byte) 0x59, (byte) 0x2a, (byte) 0x46 };

	/**
	 * Preprocess a user key into a table to save and XOR at each F-table
	 * access.
	 * 
	 * @param key
	 *            key length must be >= 10 bytes. Process the first 10 bytes.
	 */
	boolean setupKey(byte[] key) {
		int keylen = key.length;
		int i;

		if (keylen < 10)
			return false;

		if (!initialized)
			initialized = true;

		/*
		 * tab[i][c] = fTable[c ^ key[i]]
		 */
		for (i = 0; i < 10; i++) {
			int k = 0xff & key[i];
			int c;
			for (c = 0; c < 256; c++)
				tab[i][c] = fTable[c ^ k];
		}

		return true;
	}

	/**
	 * Encrypt a single block of data.
	 * <p>
	 * In and out blocks' length must be 8 bytes.
	 * 
	 * @return false if input and output blocks are null, or length is not = 8.
	 *         Else, true.
	 */
	public boolean encrypt_block(byte[] in, byte[] out) {
		int w1, w2, w3, w4;

		if (!initialized || in == null || out == null || in.length != 8
				|| in.length != out.length)
			return false;

		w1 = ((0xff & in[0]) << 8) | (0xff & in[1]);
		w2 = ((0xff & in[2]) << 8) | (0xff & in[3]);
		w3 = ((0xff & in[4]) << 8) | (0xff & in[5]);
		w4 = ((0xff & in[6]) << 8) | (0xff & in[7]);

		/* stepping rule A: */
		w1 = g0(w1);
		w4 ^= w1 ^ 1;
		w4 = g1(w4);
		w3 ^= w4 ^ 2;
		w3 = g2(w3);
		w2 ^= w3 ^ 3;
		w2 = g3(w2);
		w1 ^= w2 ^ 4;
		w1 = g4(w1);
		w4 ^= w1 ^ 5;
		w4 = g0(w4);
		w3 ^= w4 ^ 6;
		w3 = g1(w3);
		w2 ^= w3 ^ 7;
		w2 = g2(w2);
		w1 ^= w2 ^ 8;

		/* stepping rule B: */
		w2 ^= w1 ^ 9;
		w1 = g3(w1);
		w1 ^= w4 ^ 10;
		w4 = g4(w4);
		w4 ^= w3 ^ 11;
		w3 = g0(w3);
		w3 ^= w2 ^ 12;
		w2 = g1(w2);
		w2 ^= w1 ^ 13;
		w1 = g2(w1);
		w1 ^= w4 ^ 14;
		w4 = g3(w4);
		w4 ^= w3 ^ 15;
		w3 = g4(w3);
		w3 ^= w2 ^ 16;
		w2 = g0(w2);

		/* stepping rule A: */
		w1 = g1(w1);
		w4 ^= w1 ^ 17;
		w4 = g2(w4);
		w3 ^= w4 ^ 18;
		w3 = g3(w3);
		w2 ^= w3 ^ 19;
		w2 = g4(w2);
		w1 ^= w2 ^ 20;
		w1 = g0(w1);
		w4 ^= w1 ^ 21;
		w4 = g1(w4);
		w3 ^= w4 ^ 22;
		w3 = g2(w3);
		w2 ^= w3 ^ 23;
		w2 = g3(w2);
		w1 ^= w2 ^ 24;

		/* stepping rule B: */
		w2 ^= w1 ^ 25;
		w1 = g4(w1);
		w1 ^= w4 ^ 26;
		w4 = g0(w4);
		w4 ^= w3 ^ 27;
		w3 = g1(w3);
		w3 ^= w2 ^ 28;
		w2 = g2(w2);
		w2 ^= w1 ^ 29;
		w1 = g3(w1);
		w1 ^= w4 ^ 30;
		w4 = g4(w4);
		w4 ^= w3 ^ 31;
		w3 = g0(w3);
		w3 ^= w2 ^ 32;
		w2 = g1(w2);

		out[0] = (byte) (w1 >>> 8);
		out[1] = (byte) w1;
		out[2] = (byte) (w2 >>> 8);
		out[3] = (byte) w2;
		out[4] = (byte) (w3 >>> 8);
		out[5] = (byte) w3;
		out[6] = (byte) (w4 >>> 8);
		out[7] = (byte) w4;

		return true;
	}

	/**
	 * Decrypt a single block of data.
	 * <p>
	 * In and out blocks' length must be 8 bytes.
	 * 
	 * @return false if input and output blocks are null, or length is not = 8.
	 *         Else, true.
	 */
	public boolean decrypt_block(byte[] in, byte[] out) {
		int w1, w2, w3, w4;

		if (!initialized || in == null || out == null || in.length != 8
				|| in.length != out.length)
			return false;

		w1 = ((0xff & in[0]) << 8) | (0xff & in[1]);
		w2 = ((0xff & in[2]) << 8) | (0xff & in[3]);
		w3 = ((0xff & in[4]) << 8) | (0xff & in[5]);
		w4 = ((0xff & in[6]) << 8) | (0xff & in[7]);

		/* stepping rule A: */
		w2 = h1(w2);
		w3 ^= w2 ^ 32;
		w3 = h0(w3);
		w4 ^= w3 ^ 31;
		w4 = h4(w4);
		w1 ^= w4 ^ 30;
		w1 = h3(w1);
		w2 ^= w1 ^ 29;
		w2 = h2(w2);
		w3 ^= w2 ^ 28;
		w3 = h1(w3);
		w4 ^= w3 ^ 27;
		w4 = h0(w4);
		w1 ^= w4 ^ 26;
		w1 = h4(w1);
		w2 ^= w1 ^ 25;

		/* stepping rule B: */
		w1 ^= w2 ^ 24;
		w2 = h3(w2);
		w2 ^= w3 ^ 23;
		w3 = h2(w3);
		w3 ^= w4 ^ 22;
		w4 = h1(w4);
		w4 ^= w1 ^ 21;
		w1 = h0(w1);
		w1 ^= w2 ^ 20;
		w2 = h4(w2);
		w2 ^= w3 ^ 19;
		w3 = h3(w3);
		w3 ^= w4 ^ 18;
		w4 = h2(w4);
		w4 ^= w1 ^ 17;
		w1 = h1(w1);

		/* stepping rule A: */
		w2 = h0(w2);
		w3 ^= w2 ^ 16;
		w3 = h4(w3);
		w4 ^= w3 ^ 15;
		w4 = h3(w4);
		w1 ^= w4 ^ 14;
		w1 = h2(w1);
		w2 ^= w1 ^ 13;
		w2 = h1(w2);
		w3 ^= w2 ^ 12;
		w3 = h0(w3);
		w4 ^= w3 ^ 11;
		w4 = h4(w4);
		w1 ^= w4 ^ 10;
		w1 = h3(w1);
		w2 ^= w1 ^ 9;

		/* stepping rule B: */
		w1 ^= w2 ^ 8;
		w2 = h2(w2);
		w2 ^= w3 ^ 7;
		w3 = h1(w3);
		w3 ^= w4 ^ 6;
		w4 = h0(w4);
		w4 ^= w1 ^ 5;
		w1 = h4(w1);
		w1 ^= w2 ^ 4;
		w2 = h3(w2);
		w2 ^= w3 ^ 3;
		w3 = h2(w3);
		w3 ^= w4 ^ 2;
		w4 = h1(w4);
		w4 ^= w1 ^ 1;
		w1 = h0(w1);

		out[0] = (byte) (w1 >>> 8);
		out[1] = (byte) w1;
		out[2] = (byte) (w2 >>> 8);
		out[3] = (byte) w2;
		out[4] = (byte) (w3 >>> 8);
		out[5] = (byte) w3;
		out[6] = (byte) (w4 >>> 8);
		out[7] = (byte) w4;

		return true;
	}

	/**
	 * The key-dependent permutation G on V^16 is a four-round Feistel network.
	 * The round function is a fixed byte-substitution table (permutation on
	 * V^8), the F-table. Each round of G incorporates a single byte from the
	 * key.
	 */
	int g(int w, int i, int j, int k, int l) {
		w ^= 0xffff & (tab[i][w & 0xff] << 8);
		w ^= 0xff & tab[j][w >>> 8];
		w ^= 0xffff & (tab[k][w & 0xff] << 8);
		w ^= 0xff & tab[l][w >>> 8];
		return w;
	}

	int g0(int w) {
		return g(w, 0, 1, 2, 3);
	}

	int g1(int w) {
		return g(w, 4, 5, 6, 7);
	}

	int g2(int w) {
		return g(w, 8, 9, 0, 1);
	}

	int g3(int w) {
		return g(w, 2, 3, 4, 5);
	}

	int g4(int w) {
		return g(w, 6, 7, 8, 9);
	}

	/**
	 * The inverse of the G permutation.
	 */
	int h(int w, int i, int j, int k, int l) {
		w ^= 0xff & tab[l][w >>> 8];
		w ^= 0xffff & (tab[k][w & 0xff] << 8);
		w ^= 0xff & tab[j][w >>> 8];
		w ^= 0xffff & (tab[i][w & 0xff] << 8);
		return w;
	}

	int h0(int w) {
		return h(w, 0, 1, 2, 3);
	}

	int h1(int w) {
		return h(w, 4, 5, 6, 7);
	}

	int h2(int w) {
		return h(w, 8, 9, 0, 1);
	}

	int h3(int w) {
		return h(w, 2, 3, 4, 5);
	}

	int h4(int w) {
		return h(w, 6, 7, 8, 9);
	}

	public static String byte2hex(byte b) {
		final String hex = "0123456789ABCDEF";
		return "" + hex.charAt((0xf0 & b) >>> 4) + hex.charAt(0x0f & b);
	}

	public void Test() {
		byte[] inp = { (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00,
				(byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa };
		byte[] Key = { (byte) 0x00, (byte) 0x99, (byte) 0x88, (byte) 0x77,
				(byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33,
				(byte) 0x22, (byte) 0x11 };
		byte[] enc = new byte[8];
		byte[] dec = new byte[8];
		byte[] chk = { (byte) 0x25, (byte) 0x87, (byte) 0xca, (byte) 0xe2,
				(byte) 0x7a, (byte) 0x12, (byte) 0xd3, (byte) 0x00 };

		if (!setupKey(Key)) {
			System.out.println("Error: unable to set key");
			return;
		}

		encrypt_block(inp, enc);

		System.out.print("enc=");
		for (int i = 0; i < enc.length; i++)
			System.out.print(",0x" + byte2hex(enc[i]));
		System.out.println();

		System.out.print("chk=");
		for (int i = 0; i < chk.length; i++)
			System.out.print(",0x" + byte2hex(chk[i]));
		System.out.println();

		if (compareBytes(enc, chk))
			System.out.println("Skipjack test encryption is OK");
		else
			System.out.println("Skipjack test encryption failed");

		decrypt_block(enc, dec);

		if (compareBytes(dec, inp))
			System.out.println("Skipjack test decryption is OK");
		else
			System.out.println("Skipjack test decryption failed");
	}

	public static void main(String[] args) {
		Skipjack algo = new Skipjack();
		algo.Test();
	}
}