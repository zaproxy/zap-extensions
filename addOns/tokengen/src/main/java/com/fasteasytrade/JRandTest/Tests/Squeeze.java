/*
 * Created on 09/02/2005
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
 * Squeeze from DieHard
 * <p>
 * SQUEEZE TEST:  How many iterations of k=k*uni()+1 are required
 * to squeeze k down to 1, starting with k=2147483647=2^31-1.
 * <p>
 * The exact distribution of the required j is used, with
 * a chi-square test based on no_trials=100,000 tries.
 * <p>
 * The mean of j is 23.064779, with variance 23.70971151.
 *
 * @author Zur Aougav
 */

public class Squeeze extends Base
{
	final int no_trials = 100000;
	final double ratio = (double) no_trials / 1000000.0;
	final double std = sqrt(84);

	int i;
	long k;
	int j;

	int[] f = new int[43];
	double[] Ef =
		{
			21.03,
			57.79,
			175.54,
			467.32,
			1107.83,
			2367.84,
			4609.44,
			8241.16,
			13627.81,
			20968.49,
			30176.12,
			40801.97,
			52042.03,
			62838.28,
			72056.37,
			78694.51,
			82067.55,
			81919.35,
			78440.08,
			72194.12,
			63986.79,
			54709.31,
			45198.52,
			36136.61,
			28000.28,
			21055.67,
			15386.52,
			10940.20,
			7577.96,
			5119.56,
			3377.26,
			2177.87,
			1374.39,
			849.70,
			515.18,
			306.66,
			179.39,
			103.24,
			58.51,
			32.69,
			18.03,
			9.82,
			11.21 };
	double tmp;
	double chsq = 0;

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	@Override
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|                 This is the SQUEEZE test                    |");
		puts("\t| Random integers are floated to get uniforms on [0,1). Start-|");
		puts("\t| ing with k=2^31-1=2147483647, the test finds j, the number  |");
		puts("\t| of iterations necessary to reduce k to 1 using the reduction|");
		puts("\t| k=ceiling(k*U), with U provided by floating integers from   |");
		puts("\t| the file being tested.  Such j''s are found 100,000 times,  |");
		puts("\t| then counts for the number of times j was <=6,7,...,47,>=48 |");
		puts("\t| are used to provide a chi-square test for cell frequencies. |");
		puts("\t|-------------------------------------------------------------|\n");
	}

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#test(java.lang.String)
	 */
	@Override
	public void test(String filename) throws Exception
	{
		printf("\t\t\tRESULTS OF SQUEEZE TEST FOR " + filename + "\n\n");
		printf("\t\t    Table of standardized frequency counts\n");
		printf("\t\t(obs-exp)^2/exp  for j=(1,..,6), 7,...,47,(48,...)\n\t");

		openInputStream();

		for (i = 0; i < 43; ++i)
		{
			f[i] = 0;
			Ef[i] *= ratio;
		}

		for (i = 1; i <= no_trials; ++i)
		{
			k = 2147483647;
			j = 0;

			/*
			 *  squeeze k 
			 */
			while (k != 1 && j < 48)
			{
				tmp = read32BitsAsDouble();
				if (!isOpen())
					break;
				if (tmp < 0 || tmp > 1)
					printf("\ntmp < 0 || tmp > 1: " + tmp);
				k = (long) (k * tmp + 1);
				++j;
			}
			if (!isOpen())
				break;

			j = MAX(j - 6, 0);
			++f[j];
		}

		closeInputStream();

		/* 
		 * compute chi-square 
		 */
		for (i = 0; i < 43; ++i)
		{
			tmp = (f[i] - Ef[i]) / sqrt(Ef[i]);
			chsq += tmp * tmp;
			printf("\t% " + d4(tmp) + "  ");
			if ((i + 1) % 6 == 0)
				printf("\n\t");
		}

		printf(
			"\n\t\tChi-square with 42 degrees of freedom: " + d4(chsq) + "\n");
		printf(
			"\t\tz-score="
				+ d4((chsq - 42.) / std)
				+ ", p-value="
				+ d4(1 - Chisq(42, chsq))
				+ "\n");
		printf("\t_____________________________________________________________\n\n");

		return;
	}

}
