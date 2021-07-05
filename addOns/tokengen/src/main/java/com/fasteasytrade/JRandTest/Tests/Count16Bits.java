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



/**
 * Count16Bits class extends Base
 * <p>
 * count 2 bytes. 16 bits.
 *
 * @author Zur Aougav
 * */

public class Count16Bits extends Base
{

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	@Override
	public void help()
	{
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|    This is part of the Count test.  It counts consecutive   |");
		puts("\t|16 bits.                                                     |");
		puts("\t|-------------------------------------------------------------|\n");
	}

@Override
	public void runTest() throws Exception {
		final int no_seqs = 256 * 256;
		double[] v1 = new double[no_seqs]; // count each byte, 0 .. 255		
		long length = 0;

		openInputStream();

		byte b, b2;
		int temp;

		while (true)
		{
			b = readByte();
			if (!isOpen())
				break;

			b2 = readByte();
			if (!isOpen())
				break;
			length++;

			temp = ((0xff & b) << 8) | (0xff & b2);

			v1[temp]++; // increment counter
		}

		closeInputStream();

		double pv = KStest(v1, no_seqs);
		addDetail("ks test for " + no_seqs + " p's: " + pv + "\n");

		long k = length / v1.length;
		addDetail("found " + length + " 16 bits / 2 bytes.");
		addDetail("expected avg for 16 bits / 2 bytes: " + k);
		addDetail("found avg for 16 bits / 2 bytes: " + (long) avg(v1));

		// TODO work our what a Pass really is!
		if (k == 0) {
			this.setResult(Result.FAIL);
			addError("Expected avg 0 - too low");
		} else if (k == (long) avg(v1)) {
			this.setResult(Result.PASS);
		} else {
			addError("expected avg for 16 bits / 2 bytes: " + k);
			addError("found avg for 16 bits / 2 bytes: " + (long) avg(v1));
		}
		
		double t = stdev(v1, k);
		addDetail("stdev for 2 bytes\t: " + t);
		addDetail("% stdev for 2 bytes\t: %" + (100.00 * t / k));
		addDetail("chitest for 2 bytes\t: " + chitest(v1, k));
		addDetail("r2 for 2 bytes\t\t: " + r2_double(v1));

		this.setHasBeenRun(true);
	}
	
	/**
	 * @param filename input file with random data
	 */
	@Override
	public void test(String filename) throws Exception{
		printf("\t\t\tThe Count16Bits test for file " + filename + "\n");

		this.runTest();
		for (String detail : getDetails()) {
			printf("\n\t" + detail);
		}
	}

} // end class
