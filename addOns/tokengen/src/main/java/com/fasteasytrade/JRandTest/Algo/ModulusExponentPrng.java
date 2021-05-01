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

import java.math.*;
import java.util.Random;

/**
 * ModulusExponent Prng algorithm from NIST test package
 * <p>
 * Fix random p, prime, length 512 bits.
 * <p>
 * Fix random g, prime, length 512 bits. g < p.
 * <p>
 * Fix random e, prime, length 160 bits.
 * <p>
 * Each prng iteration calculate g = g**e mod p.<br>
 * The lowest 64 bits of g are the prng result.
 * 
 * @author Zur Aougav
 */
public class ModulusExponentPrng extends Cipher {

	/**
	 * p and g length/num of bits
	 */
	public final int bit_length = 512;

	/**
	 * e length/num of bits
	 */
	public final int e_bit_length = 160;

	/**
	 * prime (with probability < 2 ** -100).
	 * <p>
	 * Length of p is bit_length = 512 bits = 64 bytes.
	 */
	BigInteger p;

	/**
	 * Initial g is a random prime (with probability < 2 ** -100)
	 * <p>
	 * Length of g is bit_length = 512 bits = 64 bytes.
	 * <p>
	 * g is the "state" of the prng.
	 * <p>
	 * g = take 64 lowr bits of ( g**3 mod n ).
	 */
	BigInteger g;

	/**
	 * Initial e is a random prime (with probability < 2 ** -100)
	 * <p>
	 * Length of e is e_bit_length = 160 bits = 20 bytes.
	 * <p>
	 * e is the "exponent" of the prng.
	 */
	BigInteger e;

	/**
	 * g0 is the "initial state" of the prng.
	 * <p>
	 * reset method set g to g0.
	 */
	BigInteger g0;

	ModulusExponentPrng() {

		setup(bit_length);

	}

	ModulusExponentPrng(int x) {

		if (x < bit_length)
			setup(bit_length);
		else
			setup(x);

	}

	ModulusExponentPrng(BigInteger p, BigInteger g, BigInteger e) {

		this.p = p;
		this.g = g;
		g0 = g;
		this.e = e;

	}

	ModulusExponentPrng(BigInteger p, BigInteger g, BigInteger e, BigInteger g0) {

		this.p = p;
		this.g = g;
		this.e = e;
		this.g0 = g0;

	}

	/**
	 * Generate the keys and seed for Modulus Exponent Prng.
	 * <p>
	 * Select random primes - p, g. g < p.
	 * 
	 * @param len
	 *            length of p and g, num of bits.
	 */
	void setup(int len) {

		Random rand = new Random();

		p = BigInteger.probablePrime(len, rand);
		g = BigInteger.probablePrime(len, rand);
		e = BigInteger.probablePrime(e_bit_length, rand);

		/**
		 * if g >= p swap(g, p).
		 */
		if (g.compareTo(p) > -1) {
			BigInteger temp = g;
			g = p;
			p = temp;
		}

		/**
		 * here for sure g < p
		 */

		g0 = g;

	}

	/**
	 * calculate g**e mod p and returns lowest 64 bits, long.
	 *  
	 */
	public long nextLong() {

		g = g.modPow(e, p);

		/**
		 * set g to 2 if g <= 1.
		 */
		if (g.compareTo(BigInteger.ONE) < 1)
			g = BigInteger.valueOf(2);

		return g.longValue();

	}

	/**
	 * Public key.
	 * 
	 * @return p prime (with probability < 2 ** -100)
	 */
	public BigInteger getP() {
		return p;
	}

	/**
	 * Public key.
	 * 
	 * @return e prime (with probability < 2 ** -100)
	 */
	public BigInteger getE() {
		return e;
	}

	/**
	 * Secret key
	 * 
	 * @return g prime (with probability < 2 ** -100)
	 */
	public BigInteger getG() {
		return g;
	}

	/**
	 * Reset "state" of prng by setting g to g0 (initial g).
	 *  
	 */
	public void reset() {
		g = g0;
	}

}