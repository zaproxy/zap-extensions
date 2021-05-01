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

/**
 * Simple LCG from NIST test package
 * <p>
 * Seed to LCG is double
 * <p>
 * Each cycle returns new double.
 * 
 * @author Zur Aougav
 */
public class Lcg1Prng extends Cipher {

	/**
	 * seed contains the "state" of the LCG
	 */
	double seed = 0.0;

	/**
	 * DTWO31 = 2 ** 31
	 */
	final double DTWO31 = 2147483648.0;

	/**
	 * DTWO31M1 = 2 ** 31 - 1
	 */
	final double DTWO31M1 = 2147483647.0;

	/**
	 * DA1 = 950706376 mod 2**16
	 */
	final double DA1 = 41160.0;

	/**
	 * DA2 = 950706376 - DA1
	 */
	final double DA2 = 950665216.0;

	Lcg1Prng() {

		do {
			seed = new java.util.Random().nextDouble() * DTWO31;
			seed = Math.abs(Math.floor(seed));
		} while (seed == 0.0);

	}

	Lcg1Prng(double seed) {

		while (Math.floor(seed) == 0)
			seed = new java.util.Random().nextDouble() * DTWO31;

		this.seed = Math.abs(Math.floor(seed));

	}

	public double nextDouble() {
		
		double dz = Math.floor(seed);
		double dz1 = dz * DA1;
		double dz2 = dz * DA2;
		double dover1 = Math.floor(dz1 / DTWO31);
		double dover2 = Math.floor(dz2 / DTWO31);
		dz1 -= dover1 * DTWO31;
		dz2 -= dover2 * DTWO31;
		dz = dz1 + dz2 + dover1 + dover2;
		double dover = Math.floor(dz / DTWO31M1);
		dz -= dover * DTWO31M1;
		/*
		 * keep last calculated dz as seed to next iteration
		 */
		seed = dz;
		return dz / DTWO31M1;
	
	}

}