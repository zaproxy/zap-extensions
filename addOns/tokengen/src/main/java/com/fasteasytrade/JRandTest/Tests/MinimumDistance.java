/*
 * Created on 11/02/2005
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
 * MinimumDistance from DieHard
 * 
 * @author Zur Aougav
 * 
 */
public class MinimumDistance extends Base
{

	final int no_pts = 8000;
	final int no_smpl = 100;
	final int side = 10000;
	final double ratio = 10000.0 / UNIMAX;

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|              THE MINIMUM DISTANCE TEST                      |");
		puts("\t|It does this 100 times:  choose n=8000 random points in a    |");
		puts("\t|square of side 10000.  Find d, the minimum distance between  |");
		puts("\t|the (n^2-n)/2 pairs of points.  If the points are truly inde-|");
		puts("\t|pendent uniform, then d^2, the square of the minimum distance|");
		puts("\t|should be (very close to) exponentially distributed with mean|");
		puts("\t|.995 .  Thus 1-exp(-d^2/.995) should be uniform on [0,1) and |");
		puts("\t|a KSTEST on the resulting 100 values serves as a test of uni-|");
		puts("\t|formity for random points in the square. Test numbers=0 mod 5|");
		puts("\t|are printed but the KSTEST is based on the full set of 100   |");
		puts("\t|random choices of 8000 points in the 10000x10000 square.     |");
		puts("\t|-------------------------------------------------------------|\n");

	}

	/**
	 * class point is in Base class
	 * <p>
	 * @see com.fasteasytrade.JRandTest.Tests.Base#test(java.lang.String)
	 */
	public void test(String filename) throws Exception
	{
		point[] pts;

		int i, j, k;
		double d, dmin;
		double[] p;
		double sum = 0;
		double pvalue;

		printf(
			"\t\tThis is the MINIMUM DISTANCE test for file "
				+ filename
				+ "\n\n");
		printf("\tSample no.\t d^2\t\t mean\t\tequiv uni\n");

		openInputStream();

		pts = new point[no_pts];
		p = new double[no_smpl];

		for (i = 1; i <= no_smpl; ++i)
		{
			//dmin = 2 * side * side;
			dmin = 0x7fffffffffL;
			//int same = 0;
			for (j = 0; j < no_pts; j++)
			{
				pts[j] = new point();
				pts[j].y = ratio * (0xffffffffL & readInt());
				if (!isOpen())
				{
					System.out.println("Eof... 1");
					break;
				}
				pts[j].x = ratio * (0xffffffffL & readInt());
				if (!isOpen())
				{
					System.out.println("Eof... 2");
					break;
				}
				//if (j > 0 && pts[j].y == pts[j-1].y && pts[j].x == pts[j-1].x)
				//	same++;
			}
			if (!isOpen())
				break;
			//if (same > 0)
			//	System.out.println("same="+same+" pts.length="+pts.length);

			qsort(pts, pts.length);

			/* 
			 * find the minimum distance 
			 */
			for (j = 0; dmin > 0 && j < no_pts - 1; j++)
			{
				for (k = j + 1; dmin > 0 && k < no_pts; k++)
				{
					d = (pts[k].y - pts[j].y) * (pts[k].y - pts[j].y);
					if (d < dmin)
					{
						d += (pts[k].x - pts[j].x) * (pts[k].x - pts[j].x);
						dmin = MIN(dmin, d);
						if (dmin == 0)
							System.out.println("dmin=0 @ i="+i+" j="+j+" k="+k);
					}
				}
			}

			//dmin = sqrt(dmin);
			
			sum += dmin;
			p[i - 1] = 1 - exp(-dmin / .995); /* transforming into U[0,1] */

			if (i % 5 == 0)
				printf(
					"\n\t   "
						+ i
						+ "\t\t"
						+ d4(dmin)
						+ "\t\t"
						+ d4(sum / i)
						+ "\t\t"
						+ d4(p[i - 1]));
		}

		closeInputStream();

		puts("\n\t--------------------------------------------------------------");
		printf(
			"\n\tResult of KS test on "
				+ no_smpl
				+ " transformed mindist^2's:");
		pvalue = KStest(p, no_smpl);
		printf(" p-value=" + d4(pvalue) + "\n\n");

	}

}
