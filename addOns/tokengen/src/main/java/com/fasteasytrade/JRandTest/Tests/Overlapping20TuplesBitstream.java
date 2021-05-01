/*
 * Created on 12/02/2005
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
package com.fasteasytrade.JRandTest.Tests;

/**
 * Overlapping20TuplesBitstream from DieHard
 * <p>
 * THE OVERLAPPING 20-tuples TEST  BITSTREAM, 20 BITS PER WORD, N words
 *  <p>
 * If n=2^22, should be 19205.3 missing 20-letter words, sigma 167.
 *  <p>
 * If n=2^21, should be 141909 missing 20-letter words, sigma 428.
 *  <p>
 * If n=2^20, should be 385750 missing 20-letter words, sigma 512.
 * 
 * @author Zur Aougav
 * 
 */
public class Overlapping20TuplesBitstream extends Base
{

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|                  THE BITSTREAM TEST                         |");
		puts("\t|The file under test is viewed as a stream of bits. Call them |");
		puts("\t|b1,b2,... .  Consider an alphabet with two \"letters\", 0 and 1|");
		puts("\t|and think of the stream of bits as a succession of 20-letter |");
		puts("\t|\"words\", overlapping.  Thus the first word is b1b2...b20, the|");
		puts("\t|second is b2b3...b21, and so on.  The bitstream test counts  |");
		puts("\t|the number of missing 20-letter (20-bit) words in a string of|");
		puts("\t|2^21 overlapping 20-letter words.  There are 2^20 possible 20|");
		puts("\t|letter words.  For a truly random string of 2^21+19 bits, the|");
		puts("\t|number of missing words j should be (very close to) normally |");
		puts("\t|distributed with mean 141,909 and sigma 428.  Thus           |");
		puts("\t| (j-141909)/428 should be a standard normal variate (z score)|");
		puts("\t|that leads to a uniform [0,1) p value.  The test is repeated |");
		puts("\t|twenty times.                                                |");
		puts("\t|-------------------------------------------------------------|\n");
	}

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#test(java.lang.String)
	 */
	public void test(String filename) throws Exception
	{
		final int nb_pw = 20, power = 21, no_obs = 20;
		final int no_bits = (int) pow(2, power - 5);
		final int no_wds = (int) pow(2, power);
		final int dim = (int) pow(2, nb_pw - 5);
		int mask = (int) pow(2, nb_pw) - 1;
		final double mean = pow(2, nb_pw) * exp(-pow(2, (power - nb_pw)));
		final double std = 428;

		//int w20;
		long w20;
		int w32;
		int i, j, k, l, u, no_mswds = 0;
		int[] bitmask = new int[32];
		int[] wds = new int[dim];
		double z;

		/*
		for (i = 0; i < 32; ++i)
		{
			bitmask[i] = (int)pow(2, i);
		}
		*/
		bitmask[0] = 1;
		for (i = 1; i < 32; ++i)
			bitmask[i] = bitmask[i - 1] << 1;

		printf(
			"\t\tTHE OVERLAPPING 20-TUPLES BITSTREAM  TEST for "
				+ filename
				+ "\n");
		printf("\t (" + nb_pw + " bits/word, " + no_wds + " words");
		printf(" " + no_obs + " bitstreams.");
		printf(" No. missing words \n\t  should average " + d4(mean));
		printf(" with sigma=" + d4(std) + ".)\n");
		puts("\t----------------------------------------------------------------");
		printf("\n\t\t   Bitstream test results for " + filename + ".\n\n");
		printf("\tBitstream\tNo. missing words\tz-score\t\tp-value\n");

		openInputStream();

		//w20 = uni();
		w20 = 0xffffffffL & uni();

		/*
		 * main loop
		 */
		for (i = 1; i <= no_obs; i++)
		{
			for (j = 0; j < dim; j++)
				wds[j] = 0;

			for (j = 0; j < no_bits; ++j)
			{
				w32 = uni();
				if (!isOpen())
				{
					printf("\nError: end of file too early... End processing.\n\n");
					break;
				}

				for (k = 1; k <= 32; ++k)
				{
					w20 <<= 1;
					w20 += (w32 & 1);
					w20 &= mask;
					l = (int)(w20 & 31);
					u = (int)(w20 >>> 5);
					wds[u] |= bitmask[l];
					w32 >>>= 1;
				}
			}

			if (!isOpen())
				break;

			/*
			 * count no. of empty cells (=no. missing words)
			 */
			no_mswds = 0;
			for (j = 0; j < dim; j++)
			{
				for (k = 0; k < 32; k++)
				{
					if ((wds[j] & bitmask[k]) == 0)
						++no_mswds;
				}
			}

			z = (no_mswds - mean) / std;
			printf(
				"\t   "
					+ i
					+ "\t\t"
					+ no_mswds
					+ " \t\t\t"
					+ d4(z)
					+ "\t\t"
					+ d4(1 - Phi(z))
					+ "\n");
		}

		closeInputStream();

		puts("\t----------------------------------------------------------------");
	}

}
