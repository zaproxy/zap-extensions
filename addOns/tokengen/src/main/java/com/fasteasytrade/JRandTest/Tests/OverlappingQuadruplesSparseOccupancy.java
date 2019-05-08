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
 * OverlappingQuadruplesSparseOccupancy (OQSO) from DieHard
 *
 * @author Zur Aougav
 */
public class OverlappingQuadruplesSparseOccupancy
	extends OverlappingPairsSparseOccupancy
{

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	public void help()
	{
		puts("\n\t|------------------------------------------------------------ |");
		puts("\t|    OQSO means Overlapping-Quadruples-Sparse-Occupancy       |");
		puts("\t|  The test OQSO is similar, except that it considers 4-letter|");
		puts("\t|words from an alphabet of 32 letters, each letter determined |");
		puts("\t|by a designated string of 5 consecutive bits from the test   |");
		puts("\t|file, elements of which are assumed 32-bit random integers.  |");
		puts("\t|The mean number of missing words in a sequence of 2^21 four- |");
		puts("\t|letter words,  (2^21+3 \"keystrokes\"), is again 141909, with  |");
		puts("\t|sigma = 295.  The mean is based on theory; sigma comes from  |");
		puts("\t|extensive simulation.                                        |");
		puts("\t|------------------------------------------------------------ |\n");
	}

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.OverlappingPairsSparseOccupancy#setParameters()
	 */
	public void setParameters()
	{
		testName = "OQSO";
		bits_pl = 5;
		std = 295.0;
	}

}
