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

/**
 * MT19937Prng class java implements MT19937 prng.
 * <p>
 * Translated from C to java.
 * <p>
 * 
 * <pre>
 *  A C-program for MT19937, with initialization improved 2002/1/26.
 *  Coded by Takuji Nishimura and Makoto Matsumoto.
 * 
 *  Before using, initialize the state by using init_genrand(seed)
 *  or init_by_array(init_key, key_length).
 * 
 *  Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
 *  All rights reserved.
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 * 
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 * 
 *  3. The names of its contributors may not be used to endorse or promote
 *  products derived from this software without specific prior written
 *  permission.
 * 
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  &quot;AS IS&quot; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *  Any feedback is very welcome.
 *  http://www.math.sci.hiroshima-u.ac.jp/&tilde;m-mat/MT19937Prng/emt.html
 *  email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
 * </pre>
 */

public class MT19937Prng extends Cipher {
	/*
	 * Period parameters
	 */
	final int N = 624;

	final int M = 397;

	final long MATRIX_A = 0x9908b0dfL; /* constant vector a */

	final long UPPER_MASK = 0x80000000L; /* most significant w-r bits */

	final long LOWER_MASK = 0x7fffffffL; /* least significant r bits */

	long[] mt = new long[N]; /* the array for the state vector */

	int mti = N + 1; /* mti==N+1 means mt[N] is not initialized */

	long[] mag01 = { 0x0L, MATRIX_A };

	/* mag01[x] = x * MATRIX_A for x=0,1 */

	/**
	 * initializes mt[N] with a seed
	 */
	void init_genrand(long s) {
		mt[0] = s & 0xffffffffL;
		for (mti = 1; mti < N; mti++) {
			mt[mti] = (1812433253L * (mt[mti - 1] ^ (mt[mti - 1] >>> 30)) + mti);
			/* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
			/* In the previous versions, MSBs of the seed affect */
			/* only MSBs of the array mt[]. */
			/* 2002/01/09 modified by Makoto Matsumoto */
			mt[mti] &= 0xffffffffL;
			/* for >32 bit machines */
		}
	}

	/**
	 * initialize by an array with array-length
	 * <p>
	 * slight change for C++, 2004/2/26
	 * <p>
	 * 
	 * @param init_key
	 *            is the array for initializing keys
	 * @param key_length
	 *            is its length
	 */
	void init_by_array(long init_key[], int key_length) {
		int i, j, k;
		init_genrand(19650218L);
		i = 1;
		j = 0;
		k = (N > key_length ? N : key_length);
		for (; k != 0; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 30)) * 1664525L))
					+ init_key[j] + j;
			/*
			 * non linear
			 */
			mt[i] &= 0xffffffffL; /* for WORDSIZE > 32 machines */
			i++;
			j++;
			if (i >= N) {
				mt[0] = mt[N - 1];
				i = 1;
			}
			if (j >= key_length)
				j = 0;
		}
		for (k = N - 1; k != 0; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 30)) * 1566083941L))
					- i;
			/*
			 * non linear
			 */
			mt[i] &= 0xffffffffL; /* for WORDSIZE > 32 machines */
			i++;
			if (i >= N) {
				mt[0] = mt[N - 1];
				i = 1;
			}
		}

		/*
		 * MSB is 1; assuring non-zero initial array
		 */
		mt[0] = 0x80000000L;

	}

	/**
	 * generates a random number on [0,0xffffffff]-interval
	 */
	long genrand_int32() {
		long y;

		if (mti >= N) {
			/*
			 * generate N words at one time
			 */
			int kk;

			/*
			 * if init_genrand() has not been called, a default initial seed is
			 * used
			 */
			if (mti == N + 1)
				init_genrand(5489L);

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[(int) y & 0x01];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[(int) y & 0x01];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[(int) y & 0x01];

			mti = 0;
		}

		y = mt[mti++];

		/*
		 * Tempering
		 */
		y ^= (y >>> 11);
		y ^= (y << 7) & 0x9d2c5680L;
		y ^= (y << 15) & 0xefc60000L;
		y ^= (y >>> 18);

		return y;
	}

	/**
	 * generates a random number on [0,0x7fffffff]-interval
	 */
	long genrand_int31() {
		return genrand_int32() >>> 1;
	}

	/**
	 * generates a random number on [0,1]-real-interval
	 * <p>
	 * These real versions are due to Isaku Wada, 2002/01/09 added
	 */
	double genrand_real1() {
		/* divided by 2^32-1 */
		return genrand_int32() * (1.0 / 4294967295.0);
	}

	/**
	 * generates a random number on [0,1)-real-interval
	 * <p>
	 * These real versions are due to Isaku Wada, 2002/01/09 added
	 */
	double genrand_real2() {
		/* divided by 2^32 */
		return genrand_int32() * (1.0 / 4294967296.0);
	}

	/**
	 * generates a random number on (0,1)-real-interval
	 * <p>
	 * These real versions are due to Isaku Wada, 2002/01/09 added
	 */
	double genrand_real3() {
		/* divided by 2^32 */
		return (((double) genrand_int32()) + 0.5) * (1.0 / 4294967296.0);
	}

	/**
	 * generates a random number on [0,1) with 53-bit resolution
	 * <p>
	 * These real versions are due to Isaku Wada, 2002/01/09 added
	 */
	double genrand_res53() {
		long a = genrand_int32() >>> 5;
		long b = genrand_int32() >>> 6;
		return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
	}

	/**
	 * Test MT19937Prng PRNG
	 */
	public static void main(String[] args) {
		int i;
		long[] init = { 0x123, 0x234, 0x345, 0x456 };
		int length = 4;

		MT19937Prng m = new MT19937Prng();

		System.out.print("Init by array...\n");
		m.init_by_array(init, length);

		System.out.print("1000 outputs of genrand_int32()\n");
		for (i = 0; i < 1000; i++) {
			System.out.print("" + m.genrand_int32() + " ");
			if (i % 5 == 4)
				System.out.print("\n");
		}
		System.out.print("\n1000 outputs of genrand_real2()\n");
		for (i = 0; i < 1000; i++) {
			System.out.print("" + m.genrand_real2() + " ");
			if (i % 5 == 4)
				System.out.print("\n");
		}
	}
}