/*
 * Created on 31/03/2005
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

import java.math.*;
import java.util.Random;

/**
 * Micali-Schnorr Prng algorithm.
 * <p>
 * <p>
 * Implements algorithm directly from public published book.
 * <p>
 * The following program implements and tests the Micali-Schnorr random bits
 * generator. The test suite is according to FIPS 140-1. See "Handbook of
 * Applied Cryptography" by Alfred J. Menezes et al Section 5.4.4 pages 181 -
 * 183 and 5.37 Algorithm page 186.
 * 
 * @author Zur Aougav
 */
public class MicaliSchnorrPrng extends Cipher {

	/**
	 * n's length/num of bits
	 */
	final int bit_length = 1024;

	/**
	 * n = p * q, and calculations are done mod n.
	 */
	BigInteger n;

	/**
	 * prime (with probability < 2 ** -100)
	 */
	BigInteger p;

	/**
	 * prime (with probability < 2 ** -100)
	 */
	BigInteger q;

	/**
	 * x is the "state" of the prng.
	 * <p>
	 * x = take r high bits of ( x**e mod n ).
	 * <p>
	 * returns k random bits from k low bits of ( x**e mod n ).
	 */
	BigInteger x;

	/**
	 * x0 is the "initial state" of the prng.
	 * <p>
	 * reset method set x to x0.
	 */
	BigInteger x0;

	/**
	 * e is a random exponent we calculate on generation (in setup method)
	 */
	BigInteger e;

	/**
	 * nLength is length of n
	 */
	int nLength;

	/**
	 * nLength = r + k
	 * <p>
	 * k is the number of low bits we will use in the prng
	 */
	int k;

	/**
	 * nLength = r + k
	 * <p>
	 * r is the number of high bits we will use in the prng
	 */
	int r;

	MicaliSchnorrPrng() {

		setup(bit_length);

	}

	MicaliSchnorrPrng(int x) {

		if (x < bit_length)
			setup(bit_length);
		else
			setup(x);

	}

	MicaliSchnorrPrng(BigInteger n, BigInteger p, BigInteger q) {

		this.n = n;
		this.p = p;
		this.q = q;

	}

	MicaliSchnorrPrng(BigInteger n, BigInteger p, BigInteger q, BigInteger x) {

		this.n = n;
		this.p = p;
		this.q = q;
		this.x = x;
		x0 = x;

	}

	/**
	 * Generate the key and seed for Micali Schnorr Prng.
	 * <p>
	 * Select random p, q, n=p*q, x (mod n).
	 * 
	 * @param l
	 *            length of n, num of bits.
	 */
	boolean setup(int l) {
		if (l < 8 * 80)
			l = 8 * 80;
		int len = l / 2;
		Random rand = new Random();

		p = BigInteger.probablePrime(len, rand);
		q = BigInteger.probablePrime(len, rand);

		/*
		 * n = p * q
		 */
		n = p.multiply(q);

		/*
		 * phi = phi(n) = (p-1) * (q-1)
		 */
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(
				q.subtract(BigInteger.ONE));

		nLength = phi.bitLength() + 1;
		BigInteger NI = new BigInteger("" + nLength);
		BigInteger BI80 = new BigInteger("" + 80);

		/*
		 * find exponent e. e is a random number. 1 < e < phi. gcd(e, phi) = 1.
		 * 80e < nLength.
		 */
		BigInteger d, s;
		int counter = 0; // to control loops over 10 times
		do {
			/**
			 * control loop over 10 times. We recalculate setup method.
			 */
			if (++counter > 10)
				return setup(l);

			/**
			 * r.nextInt(nLength/80-7) is a number between 0 and nLength/80-8,
			 * so r.nextInt(nLength/80-7)+7 is a number between 7 and
			 * nLength/80-1.
			 * <p>
			 * The net result is a random e with 7 <= e < nLength/80. Hence, 80e <
			 * nLength.
			 */
			e = BigInteger.valueOf(rand.nextInt(nLength / 80 - 7) + 7);
			d = phi.gcd(e);
			s = e.multiply(BI80);
			System.out.println("random e=" + e + ", d=" + d + ", s=" + s);

		} while (d.compareTo(BigInteger.ONE) != 0 || s.compareTo(NI) >= 0);

		k = (int) (nLength * (1.0 - 2.0 / e.doubleValue()));
		r = nLength - k;

		System.out.println("nLength=" + nLength + ", r=" + r + ", k=" + k
				+ ", e=" + e);

		x = BigInteger.probablePrime(r, rand);

		x0 = x;

		return true;
	}

	/**
	 * calculate x**e mod n and returns lowest k bits, k/8 bytes, in result
	 * buffer.
	 *  
	 */
	public void getNextBits(byte[] result) {

		BigInteger y = x.modPow(e, n);

		/**
		 * nLength = r + k. r the high bits of y are kept in x. So we remove
		 * right k low bits.
		 */
		x = y.shiftRight(k);

		/**
		 * returns k low bits, k/8 bytes. we assume result length = k.8 bytes.
		 */

		byte[] array = y.toByteArray();
		int numBytes = k / 8;
		int j = array.length - numBytes;
		for (int i = 0; i < numBytes && i < result.length; i++)
			result[i] = array[j++];
	}

	/**
	 * Secret key.
	 * 
	 * @return p prime (with probability < 2 ** -100)
	 */
	public BigInteger getP() {
		return p;
	}

	/**
	 * Secret key (need only one of p or q).
	 * 
	 * @return q prime (with probability < 2 ** -100)
	 */
	public BigInteger getQ() {
		return q;
	}

	/**
	 * Public key.
	 * 
	 * @return n = p * q
	 */
	public BigInteger getN() {
		return n;
	}

	/**
	 * @return random exponent e
	 */
	public BigInteger getE() {
		return e;
	}

	/**
	 * Encryption: you need to get last x and write it to cipher output stream.
	 * <p>
	 * Decryption: you need to read "last x" from input stream, and calculate
	 * X0, the first x based on n (public key), p and q (secret key/keys).
	 * 
	 * @return current x
	 */
	public BigInteger getX() {
		return x;
	}

	/**
	 * @return length of n
	 */
	public int getNLength() {
		return nLength;
	}

	/**
	 * @return k
	 */
	public int getK() {
		return k;
	}

	/**
	 * @return r
	 */
	public int getR() {
		return r;
	}

	/**
	 * Reset "state" of prng by setting x to x0 (initial x).
	 *  
	 */
	public void reset() {
		x = x0;
	}

}