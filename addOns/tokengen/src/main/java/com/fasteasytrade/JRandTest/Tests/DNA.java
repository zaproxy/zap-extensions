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
 * DNA from DieHard
 * 
 * @author Zur Aougav
 *
 */
public class DNA extends OverlappingPairsSparseOccupancy
{

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	public void help()
	{
		puts("\n\t|------------------------------------------------------------ |");
		puts("\t|    The DNA test considers an alphabet of 4 letters: C,G,A,T,|");
		puts("\t|determined by two designated bits in the sequence of random  |");
		puts("\t|integers being tested.  It considers 10-letter words, so that|");
		puts("\t|as in OPSO and OQSO, there are 2^20 possible words, and the  |");
		puts("\t|mean number of missing words from a string of 2^21  (over-   |");
		puts("\t|lapping)  10-letter  words (2^21+9 \"keystrokes\") is 141909.  |");
		puts("\t|The standard deviation sigma=339 was determined as for OQSO  |");
		puts("\t|by simulation.  (Sigma for OPSO, 290, is the true value (to  |");
		puts("\t|three places), not determined by simulation.                 |");
		puts("\t|------------------------------------------------------------ |\n");
	}

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.OverlappingPairsSparseOccupancy#setParameters()
	 */
	public void setParameters()
	{
		testName = "DNA";
		bits_pl = 2;
		std = 339.0;
	}

}
