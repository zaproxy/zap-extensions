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

/**
 * SHA-1 Message Digest class. <br>
 * LapInt number theory library Copyright (c) 2001-2002 Lapo Luchini
 * &lt;lapo@lapo.it&gt; <br>
 * From package lapint.crypto.
 * <p>
 * Follows the <a href="http://www.itl.nist.gov/fipspubs/fip180-1.htm">FIPS PUB
 * 180-1 </a> standard which elaborates a message digest from given data (length
 * <2^64 bytes). <br>
 * As of version 1.10 I obtained the following stats using Linux 2.4.8 on a
 * P3-850:
 * <ul>
 * <li><code>21.56 Mb/s (100%)</code> Adam Back C implementation, compiled
 * with GCC 2.95 -O2</li>
 * <li><code>13.09 Mb/s ( 61%)</code> This Java implementation, compiled
 * natively with GCC 2.95 -O2</li>
 * <li><code>10.04 Mb/s ( 47%)</code> This Java implementation, compiled with
 * JIKES and executed with KAFFE JIT3</li>
 * </ul>
 * and the following stats using Win2000 on a dual P3-450:
 * <ul>
 * <li><code>14.62 Mb/s (100%)</code> Adam Back C implementation, compiled
 * with GCC 2.95 -O2</li>
 * <li><code>10.20 Mb/s ( 70%)</code> This Java implementation, compiled
 * natively with JET 2.50beta</li>
 * <li><code> 7.87 Mb/s ( 54%)</code> This Java implementation, compiled with
 * JIKES and executed with Sun JVM 1.4.0</li>
 * <li><code> 6.34 Mb/s ( 43%)</code> Sun's MessageDigest.getInstance("SHA1")
 * executed with Sun JVM 1.4.0</li>
 * </ul>
 * 
 * @author Lapo Luchini &lt;lapo@lapo.it&gt;
 */

public final class SHA1 extends Cipher implements Cloneable {

	/**
	 * Partial hash
	 */
	private int[] H;

	/**
	 * Internal buffer
	 */
	private transient int[] W;

	/**
	 * Total bytes digested
	 */
	private long totb;

	/**
	 * Wherever next update should start from scratch
	 */
	private boolean reset;

	/**
	 * Used to convert number to Hex strings
	 */
	private static char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'A', 'B', 'C', 'D', 'E', 'F' };

	/**
	 * First official test
	 */
	public final static java.lang.String TEST_0_STRING = "abc";

	/**
	 * Second official test
	 */
	public final static java.lang.String TEST_1_STRING = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

	/**
	 * Third official test
	 */
	public final static java.lang.String TEST_2_STRING = "1.000.000 repetitions of 'a'";

	/**
	 * First official test result
	 */
	public final static int[] TEST_0_HASH = { 0xA9993E36, 0x4706816A,
			0xBA3E2571, 0x7850C26C, 0x9CD0D89D };

	/**
	 * Second official test result
	 */
	public final static int[] TEST_1_HASH = { 0x84983E44, 0x1C3BD26E,
			0xBAAE4AA1, 0xF95129E5, 0xE54670F1 };

	/**
	 * Third official test result
	 */
	public final static int[] TEST_2_HASH = { 0x34AA973C, 0xD4C4DAA4,
			0xF61EEB2B, 0xDBAD2731, 0x6534016F };

	/**
	 * Creates a SHA1 object. <br>
	 * A single SHA1 object can (sequentially) elaborate many hashes.
	 */
	public SHA1() {
		H = new int[5];
		W = new int[80];
		reset = true;
	}

	public Object clone() {
		SHA1 u = null;
		try {
			u = (SHA1) super.clone();
			u.H = new int[5];
			System.arraycopy(H, 0, u.H, 0, 5);
			u.W = new int[80];
			System.arraycopy(W, 0, u.W, 0, 80);
		} catch (CloneNotSupportedException e) {
		}
		return (u);
	}

	/**
	 * Returns the digest and resets the object to calculate another digest.
	 * <br>
	 * The array returned will NOT be reused by this object. <br>
	 * Please note that calculating the digest finalizes the digest and next
	 * {@link #update(byte[]) update()}will start from scratch. <br>
	 * You can use {@link #clone()}to get partial digests. <br>
	 * 
	 * @return byte[20] array containing the required hash
	 */
	public byte[] digest8() {
		if (!reset)
			digest_finalize();
		byte[] out = new byte[20];
		for (int i = 0; i < 20; i++)
			out[i] = (byte) ((H[i >> 2] >> (8 * (3 - (i & 3)))) & 0xFF);
		return (out);
	}

	/**
	 * Returns the digest and resets the object to calculate another digest.
	 * <br>
	 * The array returned will NOT be reused by this object. <br>
	 * Please note that calculating the digest finalizes the digest and next
	 * {@link #update(byte[]) update()}will start from scratch. <br>
	 * You can use {@link #clone()}to get partial digests. <br>
	 * 
	 * @return int[5] array containing the required hash
	 */
	public int[] digest32() {
		if (!reset)
			digest_finalize();
		int[] out = new int[5];
		System.arraycopy(H, 0, out, 0, 5);
		return (out);
	}

	/**
	 * Finalize the hash calculation, as defined in the standard.
	 */
	private void digest_finalize() {
		if (reset)
			return;
		int bufs = ((int) totb) & 63;
		int i = bufs & 3;
		if (i == 0)
			W[bufs >> 2] = 0;
		// add final '1' bit
		W[bufs >> 2] |= 0x80 << ((~i) << 3);
		bufs++;
		// check for space for last 2 words
		if (bufs > 56) {
			// zero pad the segment
			for (i = (bufs + 3) >> 2; i < 16; i++)
				W[i] = 0;
			update_buffers();
			bufs = 0;
		}
		// zero pads up to 14 words
		for (i = (bufs + 3) >> 2; i < 14; i++)
			W[i] = 0;
		// add two words with hash length in bits
		totb <<= 3; // bytes to bits, changing it is OK as it is to be resetted
		// to 0 before next use
		W[14] = (int) (totb >>> 32);
		W[15] = (int) (totb & 0xFFFFFFFF);
		update_buffers();
		reset = true;
	}

	public void update(byte m) {
		byte[] v = new byte[1];
		v[0] = m;
		update(v);
	}

	/**
	 * init internal buffer with IV (of bytes)
	 * 
	 * @param m
	 *            IV vector of bytes
	 */
	public void init(byte[] m) {
		for (int i = 0; i < H.length; i++) {
			H[i] = (0xff & m[i * 4]) >>> 24;
			H[i] |= ((0xff & m[i * 4 + 1]) >>> 16);
			H[i] |= ((0xff & m[i * 4 + 2]) >>> 8);
			H[i] |= (0xff & m[i * 4 + 3]);
		}
		totb = 0;
		reset = false;
	}

	/**
	 * init internal buffer with IV (of ints)
	 * 
	 * @param m
	 *            IV vector of integers (32 bits)
	 */
	public void init(int[] m) {
		for (int i = 0; i < H.length; i++)
			H[i] = m[i];
		totb = 0;
		reset = false;
	}

	/**
	 * Feeds more bytes to the digest.
	 * 
	 * @param m
	 *            bytes to elaborate (any length is valid)
	 */
	public void update(byte[] m) {
		if (reset) {
			H[0] = 0x67452301;
			H[1] = 0xEFCDAB89;
			H[2] = 0x98BADCFE;
			H[3] = 0x10325476;
			H[4] = 0xC3D2E1F0;
			totb = 0;
			reset = false;
		}

		int i = 0, t = ((int) totb) & 63;
		while ((i < m.length) && ((t & 3) != 0)) { // up to dword alignement or
			// end
			W[t >> 2] |= m[i] << (((~(int) totb) & 3) << 3); // add next byte
			i++;
			totb++;
			t = ((int) totb) & 63;
			if (t == 0) // buffer full
				update_buffers();
		}
		while (i + 3 < m.length) { // full dword available
			W[t >> 2] = (m[i] << 24) | ((m[i + 1] & 0xFF) << 16)
					| ((m[i + 2] & 0xFF) << 8) | (m[i + 3] & 0xFF);
			i += 4;
			totb += 4;
			t = ((int) totb) & 63;
			if (t == 0) // buffer full
				update_buffers();
		}
		if (i < m.length)
			W[t >> 2] = 0;
		while (i < m.length) { // last unaligned bytes
			W[t >> 2] |= m[i] << (((~(int) totb) & 3) << 3); // add next byte
			i++;
			totb++;
			t = ((int) totb) & 63;
			if (t == 0) // buffer full
				update_buffers();
		}
	}

	/**
	 * Updates the hash with more ints (big-endian).
	 * 
	 * @param m
	 *            an array of ints to add
	 */
	public void update(int[] m) {
		byte[] vect = new byte[4];
		//TODO optimize in buffer already dword-aligned
		for (int i = 0; i < m.length; i++) {
			vect[0] = (byte) ((m[i] >> 24) & 0xFF);
			vect[1] = (byte) ((m[i] >> 16) & 0xFF);
			vect[2] = (byte) ((m[i] >> 8) & 0xFF);
			vect[3] = (byte) ((m[i]) & 0xFF);
			update(vect);
		}
	}

	/**
	 * Updates the hash with more longs (big-endian).
	 * 
	 * @param m
	 *            an array of ints to add
	 */
	public void update(long[] m) {
		byte[] vect = new byte[8];
		//TODO optimize in buffer already dword-aligned
		for (int i = 0; i < m.length; i++) {
			vect[0] = (byte) ((m[i] >> 56) & 0xFF);
			vect[1] = (byte) ((m[i] >> 48) & 0xFF);
			vect[2] = (byte) ((m[i] >> 40) & 0xFF);
			vect[3] = (byte) ((m[i] >> 32) & 0xFF);
			vect[4] = (byte) ((m[i] >> 24) & 0xFF);
			vect[5] = (byte) ((m[i] >> 16) & 0xFF);
			vect[6] = (byte) ((m[i] >> 8) & 0xFF);
			vect[7] = (byte) ((m[i]) & 0xFF);
			update(vect);
		}
	}

	/**
	 * Internally used when the buffer is ready for the digest. <br>
	 * Completely unrolled for maximum performance.
	 */
	private final void update_buffers() {
		for (int i = 16; i < 80; i++) {
			W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
			W[i] = (W[i] << 1) | (W[i] >>> 31);
		}

		int A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];

		// This completely unrolled version makes the program 23% faster overall
		// (and a little bigger, of course; calculated with version 1.10)
		E += W[0] + ((A << 5) | (A >>> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		D += W[1] + ((E << 5) | (E >>> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		C += W[2] + ((D << 5) | (D >>> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		B += W[3] + ((C << 5) | (C >>> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		A += W[4] + ((B << 5) | (B >>> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		E += W[5] + ((A << 5) | (A >>> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		D += W[6] + ((E << 5) | (E >>> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		C += W[7] + ((D << 5) | (D >>> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		B += W[8] + ((C << 5) | (C >>> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		A += W[9] + ((B << 5) | (B >>> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		E += W[10] + ((A << 5) | (A >>> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		D += W[11] + ((E << 5) | (E >>> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		C += W[12] + ((D << 5) | (D >>> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		B += W[13] + ((C << 5) | (C >>> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		A += W[14] + ((B << 5) | (B >>> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		E += W[15] + ((A << 5) | (A >>> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		D += W[16] + ((E << 5) | (E >>> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		C += W[17] + ((D << 5) | (D >>> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		B += W[18] + ((C << 5) | (C >>> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		A += W[19] + ((B << 5) | (B >>> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		E += W[20] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		D += W[21] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		C += W[22] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		B += W[23] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		A += W[24] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		E += W[25] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		D += W[26] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		C += W[27] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		B += W[28] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		A += W[29] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		E += W[30] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		D += W[31] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		C += W[32] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		B += W[33] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		A += W[34] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		E += W[35] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		D += W[36] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		C += W[37] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		B += W[38] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		A += W[39] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		E += W[40] + ((A << 5) | (A >>> 27)) + ((B & (C | D)) | (C & D))
				+ 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		D += W[41] + ((E << 5) | (E >>> 27)) + ((A & (B | C)) | (B & C))
				+ 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		C += W[42] + ((D << 5) | (D >>> 27)) + ((E & (A | B)) | (A & B))
				+ 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		B += W[43] + ((C << 5) | (C >>> 27)) + ((D & (E | A)) | (E & A))
				+ 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		A += W[44] + ((B << 5) | (B >>> 27)) + ((C & (D | E)) | (D & E))
				+ 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		E += W[45] + ((A << 5) | (A >>> 27)) + ((B & (C | D)) | (C & D))
				+ 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		D += W[46] + ((E << 5) | (E >>> 27)) + ((A & (B | C)) | (B & C))
				+ 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		C += W[47] + ((D << 5) | (D >>> 27)) + ((E & (A | B)) | (A & B))
				+ 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		B += W[48] + ((C << 5) | (C >>> 27)) + ((D & (E | A)) | (E & A))
				+ 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		A += W[49] + ((B << 5) | (B >>> 27)) + ((C & (D | E)) | (D & E))
				+ 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		E += W[50] + ((A << 5) | (A >>> 27)) + ((B & (C | D)) | (C & D))
				+ 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		D += W[51] + ((E << 5) | (E >>> 27)) + ((A & (B | C)) | (B & C))
				+ 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		C += W[52] + ((D << 5) | (D >>> 27)) + ((E & (A | B)) | (A & B))
				+ 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		B += W[53] + ((C << 5) | (C >>> 27)) + ((D & (E | A)) | (E & A))
				+ 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		A += W[54] + ((B << 5) | (B >>> 27)) + ((C & (D | E)) | (D & E))
				+ 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		E += W[55] + ((A << 5) | (A >>> 27)) + ((B & (C | D)) | (C & D))
				+ 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		D += W[56] + ((E << 5) | (E >>> 27)) + ((A & (B | C)) | (B & C))
				+ 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		C += W[57] + ((D << 5) | (D >>> 27)) + ((E & (A | B)) | (A & B))
				+ 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		B += W[58] + ((C << 5) | (C >>> 27)) + ((D & (E | A)) | (E & A))
				+ 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		A += W[59] + ((B << 5) | (B >>> 27)) + ((C & (D | E)) | (D & E))
				+ 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		E += W[60] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		D += W[61] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		C += W[62] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		B += W[63] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		A += W[64] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);
		E += W[65] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		D += W[66] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		C += W[67] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		B += W[68] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		A += W[69] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);
		E += W[70] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		D += W[71] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		C += W[72] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		B += W[73] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		A += W[74] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);
		E += W[75] + ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		D += W[76] + ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		C += W[77] + ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		B += W[78] + ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		A += W[79] + ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);

		H[0] += A;
		H[1] += B;
		H[2] += C;
		H[3] += D;
		H[4] += E;
	}

	/**
	 * Method to self-test the class from command line.
	 * 
	 * @param args
	 *            command line parameters
	 */
	public static void main(String[] args) {
		if (args.length == 0)
			selfTest();
		else {
			SHA1 sha = new SHA1();
			sha.update(args[0].getBytes());
			System.out.println(SHA1.toHex(sha.digest8()));
		}
	}

	/**
	 * Self test using standard tests and write to standard output the result.
	 */
	public static void selfTest() {
		SHA1 sha = new SHA1();
		byte[] hash8;
		int[] hash32;
		int i;
		sha.update(TEST_0_STRING.getBytes());
		hash8 = sha.digest8();
		System.out.println(TEST_0_STRING + " => " + SHA1.toHex(hash8));
		for (i = 0; i < 20; i += 4)
			if (((hash8[i] << 24) | ((hash8[i + 1] & 0xFF) << 16)
					+ ((hash8[i + 2] & 0xFF) << 8) + (hash8[i + 3] & 0xFF)) != TEST_0_HASH[i >> 2])
				throw (new RuntimeException("Hash0 not valid (in 8 bit form)."));
		hash32 = sha.digest32();
		for (i = 0; i < 5; i++)
			if (hash32[i] != TEST_0_HASH[i])
				throw (new RuntimeException("Hash0 not valid (in 32 bit form)."));
		sha.update(TEST_1_STRING.getBytes());
		hash32 = sha.digest32();
		for (i = 0; i < 5; i++)
			if (hash32[i] != TEST_1_HASH[i])
				throw (new RuntimeException("Hash1 not valid (in 32 bit form)."));
		hash8 = sha.digest8();
		System.out.println(TEST_1_STRING + " => " + SHA1.toHex(hash8));
		for (i = 0; i < 20; i += 4)
			if (((hash8[i] << 24) | ((hash8[i + 1] & 0xFF) << 16)
					+ ((hash8[i + 2] & 0xFF) << 8) + (hash8[i + 3] & 0xFF)) != TEST_1_HASH[i >> 2])
				throw (new RuntimeException("Hash1 not valid (in 8 bit form)."));
		byte[] s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				.getBytes();
		for (i = 0; i < 5000; i++)
			sha.update(s);
		sha = (SHA1) sha.clone();
		for (i = 0; i < 5000; i++)
			sha.update(s);
		hash8 = sha.digest8();
		System.out.println(TEST_2_STRING + " => " + SHA1.toHex(hash8));
		for (i = 0; i < 20; i += 4)
			if (((hash8[i] << 24) | ((hash8[i + 1] & 0xFF) << 16)
					+ ((hash8[i + 2] & 0xFF) << 8) + (hash8[i + 3] & 0xFF)) != TEST_2_HASH[i >> 2])
				throw (new RuntimeException("Hash2 not valid (in 8 bit form)."));
		hash32 = sha.digest32();
		for (i = 0; i < 5; i++)
			if (hash32[i] != TEST_2_HASH[i])
				throw (new RuntimeException("Hash2 not valid (in 32 bit form)."));
		long tm = System.currentTimeMillis(), tmn;
		i = 0;
		while ((tmn = (System.currentTimeMillis() - tm)) < 2000)
			for (int j = 0; j < 100; j++, i++)
				sha.update(s);
		hash32 = sha.digest32();
		tmn = System.currentTimeMillis() - tm;
		tmn = (s.length * i * 1000L) / tmn; // speed in bytes/s
		tmn = tmn * 100L >> 20; // speed in 0.01 Mb/s
		System.out.print("All is OK (" + (tmn / 100) + ".");
		tmn = tmn % 100;
		if (tmn < 10)
			System.out.print("0");
		System.out.println((tmn % 100) + " Mb/s).");
	}

	/**
	 * Formats a number in an hex string.
	 * 
	 * @param v
	 *            number to format
	 * @return hex string of the number
	 */
	public final static String toHex(byte[] v) {
		String out = "";
		for (int i = 0; i < v.length; i++)
			out = out + hex[(v[i] >> 4) & 0xF] + hex[v[i] & 0xF];
		return (out);
	}

	/**
	 * get internal hash vector
	 * 
	 * @return internal hash vector
	 */
	public int[] getH() {
		return H;
	}

	/**
	 * get internal hash vector as vector of bytes
	 * 
	 * @return internal hash vector
	 */
	public byte[] getHAsBytes() {
		byte[] v = new byte[H.length * 4];
		for (int i = 0; i < H.length; i++) {
			v[i * 4] = (byte) (H[i] >>> 24);
			v[i * 4 + 1] = (byte) (H[i] >>> 16);
			v[i * 4 + 2] = (byte) (H[i] >>> 8);
			v[i * 4 + 3] = (byte) H[i];
		}
		return v;
	}

	/**
	 * get internal hash vector as vector of bytes
	 * 
	 * @param v
	 *            H interbnal vector is copied into v
	 */
	public void getHAsBytes(byte[] v) {
		for (int i = 0; i < H.length; i++) {
			v[i * 4] = (byte) (H[i] >>> 24);
			v[i * 4 + 1] = (byte) (H[i] >>> 16);
			v[i * 4 + 2] = (byte) (H[i] >>> 8);
			v[i * 4 + 3] = (byte) H[i];
		}
	}

}