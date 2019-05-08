/*
 * Created on 30/03/2005
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
 * BBS encryption algorithm.
 * <p>
 * The following program implements the Blum-Blum-Shub random bits generator.
 * The test suite is according to FIPS 140-1. See "Handbook of Applied
 * Cryptography" by Alfred J. Menezes et al Section 5.4.4 pages 181 - 183 and
 * 5.40 Algorithm page 186.
 * 
 * @author Zur Aougav
 */
public class BBSPrng extends Cipher {

	/**
	 * n's length/num of bits
	 */
	final int bit_length = 256;

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
	 * x is the "state" of the prng. x = x**2 mod n.
	 */
	BigInteger x;

	/**
	 * x0 is the "initial state" of the prng.
	 * <p>
	 * reset method set x to x0.
	 */
	BigInteger x0;

	BBSPrng() {

		setup(bit_length);

	}

	BBSPrng(int x) {

		if (x < bit_length)
			setup(bit_length);
		else
			setup(x);

	}

	BBSPrng(BigInteger n, BigInteger p, BigInteger q) {

		this.n = n;
		this.p = p;
		this.q = q;

	}

	BBSPrng(BigInteger n, BigInteger p, BigInteger q, BigInteger x) {

		this.n = n;
		this.p = p;
		this.q = q;
		this.x = x;
		x0 = x;

	}

	/**
	 * select random p, q, n=p*q, x (mod n).
	 * 
	 * @param l
	 *            length of n, num of bits.
	 */
	void setup(int l) {
		int len = l / 2;
		Random r = new Random();

		p = BigInteger.probablePrime(len, r);
		q = BigInteger.probablePrime(len, r);

		/*
		 * n = p * q
		 */
		n = p.multiply(q);

		/*
		 * find "random" x mod n
		 */
		x = BigInteger.valueOf(r.nextLong());
		for (int i = 0; i < 10 || x.compareTo(BigInteger.ONE) < 1; i++)
			x = x.multiply(BigInteger.valueOf(r.nextLong())).mod(n);

		x = x.multiply(x).mod(n);

		x0 = x;
	}

	/**
	 * calculate x**2 mod n and returns lowest 64 bits.
	 * 
	 * @return next long, 64 bits
	 */
	public long nextLong() {

		x = x.multiply(x).mod(n);

		return x.longValue();

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
	 * @param x
	 *            new x0
	 */
	public void setX(BigInteger x) {
		this.x = x;
	}

	/**
	 * Reset "state" of prng by setting x to x0 (initial x).
	 *  
	 */
	public void reset() {
		x = x0;
	}

}