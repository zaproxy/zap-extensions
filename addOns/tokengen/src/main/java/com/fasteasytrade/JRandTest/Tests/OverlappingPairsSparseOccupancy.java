/*
 * Created on 13/02/2005
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
 * OverlappingPairsSparseOccupancy (OPSO) from DieHard
 *
 * @author Zur Aougav
 */
public class OverlappingPairsSparseOccupancy extends Base
{

	final int bits_pw = 20;
	final double mean = pow(2, bits_pw) * exp(-2);
	final int dim = (int) pow(2, bits_pw - 5);
	final int no_tests = 1;

	/**
	 * The algorithms OPSO, OQSO and DNA use 3 parameters set in
	 * setParameters.
	 */
	public String testName = "OPSO"; // will be OPSO, OQSO, DNA.
	public int bits_pl = 10;
	public double std = 290.0;

	// used by get_w 
	int flag = -1, ltrs_pw;
	int wd, maskltr;
	//	end used by get_w

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|        OPSO means Overlapping-Pairs-Sparse-Occupancy        |");
		puts("\t|The OPSO test considers 2-letter words from an alphabet of   |");
		puts("\t|1024 letters.  Each letter is determined by a specified ten  |");
		puts("\t|bits from a 32-bit integer in the sequence to be tested. OPSO|");
		puts("\t|generates  2^21 (overlapping) 2-letter words  (from 2^21+1   |");
		puts("\t|\"keystrokes\")  and counts the number of missing words---that |");
		puts("\t|is 2-letter words which do not appear in the entire sequence.|");
		puts("\t|That count should be very close to normally distributed with |");
		puts("\t|mean 141,909, sigma 290. Thus (missingwrds-141909)/290 should|");
		puts("\t|be a standard normal variable. The OPSO test takes 32 bits at|");
		puts("\t|a time from the test file and uses a designated set of ten   |");
		puts("\t|consecutive bits. It then restarts the file for the next de- |");
		puts("\t|signated 10 bits, and so on.                                 |");
		puts("\t|------------------------------------------------------------ |\n");
	}

	/**
	 * Different parameters set by 3 algorithms: OPSO, OQSO and DNA.
	 */
	public void setParameters()
	{
		testName = "OPSO";
		bits_pl = 10;
		std = 290.0;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#test(java.lang.String)
	 */
	public void test(String filename)
	{
		int j;
		int u, l;
		int wd;
		long[] maskbit = new long[32];
		int i, k, rt = 0;
		int no_wds = (int) pow(2, bits_pw + 1);
		int no_mswds;
		int[] wds;
		double z;

		/*
		 * set different parameters in differentt classes
		 */
		setParameters();

		printf("\t\t\t   " + testName + " test for file " + filename + "\n\n");
		printf("\tBits used\tNo. missing words");
		printf("\tz-score\t\tp-value\n");

		maskbit[0] = 1;
		for (j = 1; j < 32; j++)
			maskbit[j] = maskbit[j - 1] * 2;

		wds = new int[dim];

		do
		{
			openInputStream();

			for (i = 1; i <= no_tests; i++)
			{
				for (j = 0; j < dim; j++)
				{
					wds[j] = 0;
				}

				for (j = 1; j <= no_wds; j++)
				{
					wd = get_w( rt );
					l = wd & 31;
					u = wd >>> 5;
					wds[u] |= maskbit[l];
				}

				/*
				 * count no. of empty cells (equals no. missing words)
				 */
				no_mswds = 0;
				for (j = 0; j < dim; j++)
				{
					for (k = 0; k < 32; k++)
					{
						if ((wds[j] & maskbit[k]) == 0)
							no_mswds++;
					}
				}

				z = (no_mswds - mean) / std;
				printf(
					"\t"
						+ (33 - rt - bits_pl)
						+ " to "
						+ (32 - rt)
						+ "  \t\t"
						+ (no_mswds)
						+ " ");
				printf("\t\t" + d4(z) + "\t\t" + d4(1 - Phi(z)) + "\n");
			}

			closeInputStream();

			rt++;
		}
		while (rt <= 32 - bits_pl);

		printf("\t------------------------------");
		printf("-----------------------------------\n");
	}

	/**
	 * get a word from specific bits 
	 */
	public int get_w(int rt)
	{
		wd <<= bits_pl;

		if (flag != rt)
		{
			flag = rt;
			maskltr = (int) pow(2, bits_pl) - 1;
			ltrs_pw = 20 / bits_pl;

			for (int i = 1; i < ltrs_pw; i++)
			{
				wd += (uni() >>> rt) & maskltr;
				wd <<= bits_pl;
			}
		}

		wd += (uni() >>> rt) & maskltr;

		/* 
		 * 1048575 = 2**20-1 
		 */
		return (wd & 1048575);
	}

}
