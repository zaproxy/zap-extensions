/*
 * Created on 03/02/2005
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

import com.fasteasytrade.JRandTest.Utils.Derf;

/**
 * Count1Bit class extends Base
 * <p>
 * count each bit, the 0's and 2's
 *
 * @author Zur Aougav 
 */

public class Count1Bit extends Base
{

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	@Override
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|    This is part of the Count test.  It counts the bits, 0's |");
		puts("\t|and 1's. The sums and the differences are reported. The      |");
		puts("\t|expection is 50%, each sum from total bits.                  |");
		puts("\t|-------------------------------------------------------------|\n");
	}

@Override
	public void runTest() {
		final int no_seqs = 2;
		double[] v4 = new double[no_seqs]; // count bit 0's and 1's
		int j;
		long length = 0;
	
		openInputStream();
	
		byte b;
		int temp;
	
		while (true) {
			b = readByte();
			if (!isOpen())
				break;
			length += 8;
	
			temp = 0xff & b;
			for (j = 0; j < 8; j++)
			{
				v4[temp & 1]++; // increment counter 0 or 1
				temp = temp >>> 1; // drop 1 bit from temp
			}
		}
	
		closeInputStream();
	
		double pv = KStest(v4, no_seqs);
		addDetail("ks test for " + no_seqs + " p's: " + d4(pv) + "\n");
	
		//addDetail("\n\t count bits 0&1. Should be: " + length * 4);
		long k = length / v4.length;
		addDetail("found " + length + " 1 bit.");
		addDetail("expected avg for 1 bit : " + k);
		addDetail("found avg for 1 bit    : " + (long) avg(v4));
		// TODO work our what a Pass really is!
		if (k == 0) {
			this.setResult(Result.FAIL);
			addError("Expected avg 0 - too low");
		} else if (k == avg(v4)) {
			this.setResult(Result.PASS);
		} else {
			addError("expected avg for 1 bit : " + k);
			addError("found avg for 1 bit    : " + (long) avg(v4));
		}
		for (j = 0; j < no_seqs; j++)
			addDetail(
				"bit "
					+ j
					+ ": "
					+ d4(v4[j])
					+ " delta: "
					+ d4(v4[j] - k)
					+ " %: "
					+ d4((100.00 * v4[j] / k - 100.00)));
	
		addDetail("the sum is\t\t: " + (long) (v4[1] - v4[0]));
		addDetail(
			"% sum/n is\t\t: %"
				+ d4(100 * (v4[1] - v4[0]) / (double) length));
	
		double t = stdev(v4, k);
		addDetail("stdev for 1 bit  \t:  " + d4(t));
		addDetail("% stdev for 1 bit\t: %" + d4(100.00 * t / k));
		addDetail("chitest for 1 bit\t:  " + d4(chitest(v4, k)));
		addDetail("r2 for 1 bit\t\t:  " + d4(r2_double(v4)));
	
		double e = ABS(v4[1] - v4[0]) / sqrt(2.0 * length);
		e = Derf.derfc(e);
		addDetail("pValue (erfc)\t\t:  " + d4(e));
	
		this.setHasBeenRun(true);
	}
	
	/**
	 * @param filename input file with random data
	 */
	@Override
	public void test(String filename) throws Exception{
		printf("\t\t\tThe Count1Bit test for file " + filename + "\n");
		this.runTest();
		for (String detail : getDetails()) {
			printf("\n\t" + detail);
		}
	}

} // end class
