/*
 * Created on 31/01/2005
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
 * Run from DieHard
 * <p>
 * Run class extends Base<br>
 * count the number of runs and compute the statistics<br>
 * Algorithm AS 157 Appl. Statist. (1981) vol. 30, No. 1
 * 
 * @author Zur Aougav
 */

public class Run extends Base
{
	/**
	 * @param x array of doubles
	 * @param length is length of array x
	 * @param ustat array with one double, to return value to caller
	 * @param dstat array with one double, to return value to caller
	 */
	public void udruns(double[] x, int length, double[] ustat, double[] dstat)
		throws Exception
	{
		int ru = 0;
		int rd = 0;
		int i;
		int j;
		int[] ucnt;
		int[] dcnt;

		double up;
		double[][] a = { { 4529.4, 9044.9, 13568., 18091., 22615., 27892. }, {
				9044.9, 18097., 27139., 36187., 45234., 55789. }, {
				13568., 27139., 40721., 54281., 67852., 83685. }, {
				18091., 36187., 54281., 72414., 90470., 111580. }, {
				22615., 45234., 67852., 90470., 113262., 139476. }, {
				27892., 55789., 83685., 111580., 139476., 172860. }
		};

		double[] b =
			{ 1. / 6, 5. / 24, 11. / 120, 19. / 720, 29. / 5040, 1. / 840 };

		if (length < 4000)
		{
			puts("Length of the sequence is too short (< 4000)!!!");
			throw new Exception("Length of the sequence is too short (< 4000)!!!");
			//System.exit(0);
		}

		ucnt = new int[6];
		dcnt = new int[6];

		/*
		 * The loop determines the number of runs-up and runs-down of 
		 * length i for i = 1(1)5 and the number of runs-up and runs-down
		 * of length greater than or equal to 6. 
		 */

		for (i = 1; i < length; ++i)
		{
			up = x[i] - x[i - 1];

			/* 
			 * this does not happen actually. it is included for logic reason 
			 */
			if (up == 0)
			{
				if (x[i] <= .5)
					up = -1;
				else
					up = 1;
			}

			if (up > 0)
			{
				++dcnt[rd];
				rd = 0;
				ru = MIN(ru + 1, 5);
				continue;
			}

			if (up < 0)
			{
				++ucnt[ru];
				ru = 0;
				rd = MIN(rd + 1, 5);
				continue;
			}
		}

		++ucnt[ru];
		++dcnt[rd];

		/*
		 * calculate the test-stat
		 */
		ustat[0] = 0;
		dstat[0] = 0;
		for (i = 0; i < 6; ++i)
		{
			for (j = 0; j < 6; ++j)
			{
				ustat[0] += (ucnt[i] - length * b[i])
					* (ucnt[j] - length * b[j])
					* a[i][j];
				dstat[0] += (dcnt[i] - length * b[i])
					* (dcnt[j] - length * b[j])
					* a[i][j];
			}
		}

		ustat[0] /= length;
		dstat[0] /= length;

	} // end udruns

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	@Override
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|    This is the RUNS test.  It counts runs up, and runs down,|");
		puts("\t|in a sequence of uniform [0,1) variables, obtained by float- |");
		puts("\t|ing the 32-bit integers in the specified file. This example  |");
		puts("\t|shows how runs are counted: .123,.357,.789,.425,.224,.416,.95|");
		puts("\t|contains an up-run of length 3, a down-run of length 2 and an|");
		puts("\t|up-run of (at least) 2, depending on the next values.  The   |");
		puts("\t|covariance matrices for the runs-up and runs-down are well   |");
		puts("\t|known, leading to chisquare tests for quadratic forms in the |");
		puts("\t|weak inverses of the covariance matrices.  Runs are counted  |");
		puts("\t|for sequences of length 10,000.  This is done ten times. Then|");
		puts("\t|another three sets of ten.                                   |");
		puts("\t|-------------------------------------------------------------|\n");

	}
	/**
	 * @param filename input file with random data
	 */
	@Override
	public void test(String filename) throws Exception
	{
		final int no_sets = 2;
		final int no_seqs = 10;
		final int length = 10000;

		int i, j, k;
		double[] x;
		double[] ustat = new double[1];
		double[] dstat = new double[1];
		double[] pu;
		double[] pd;
		double pv;

		printf("\t\t\tThe RUNS test for file " + filename + "\n");
		puts("\t\t(Up and down runs in a sequence of 10000 numbers)");

		openInputStream();
		
		x = new double[length];
		pu = new double[no_seqs];
		pd = new double[no_seqs];

		for (i = 1; i <= no_sets; ++i)
		{
			for (j = 0; j < no_seqs; ++j)
			{
				for (k = 0; k < length; ++k)
				{
if (!rs.isOpen()) {
	System.out.println("SBSB closed!");
	break;
}
					//x[k] = uni() / (0.000 + UNIMAX);
					x[k] = read32BitsAsDouble();
					//System.out.println("x["+k+"]="+x[k]);
System.out.println("x["+k+"]="+x[k]);
				}

				udruns(x, length, ustat, dstat);
				pu[j] = Chisq(6, ustat[0]);
				pd[j] = Chisq(6, dstat[0]);
			}

			pv = KStest(pu, no_seqs);
			printf("\n\t\t\t\tSet " + i + "\n");
			printf(
				"\t\t runs up; ks test for " + no_seqs + " p's: " + pv + "\n");
			pv = KStest(pd, no_seqs);
			printf(
				"\t\t runs down; ks test for "
					+ no_seqs
					+ " p's: "
					+ pv
					+ "\n");
		}

		closeInputStream();

		return;
	}

} // end class
