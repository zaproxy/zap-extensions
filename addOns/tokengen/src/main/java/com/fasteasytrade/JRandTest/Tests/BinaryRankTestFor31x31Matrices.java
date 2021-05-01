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
 * BinaryRankTestFor31x31Matrices from DieHard
 * 
 * @author Zur Aougav
 *  
 */
public class BinaryRankTestFor31x31Matrices extends
		BinaryRankTestFor6x8Matrices {

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.Base#help()
	 */
	public void help() {
		puts("\n\t|-------------------------------------------------------------|");
		puts("\t|This is the BINARY RANK TEST for 31x31 matrices. The leftmost|");
		puts("\t|31 bits of 31 random integers from the test sequence are used|");
		puts("\t|to form a 31x31 binary matrix over the field {0,1}. The rank |");
		puts("\t|is determined. That rank can be from 0 to 31, but ranks< 28  |");
		puts("\t|are rare, and their counts are pooled with those for rank 28.|");
		puts("\t|Ranks are found for 40,000 such random matrices and a chisqu-|");
		puts("\t|are test is performed on counts for ranks 31,30,28 and <=28. |");
		puts("\t|-------------------------------------------------------------|");
	}

	/**
	 * @see com.fasteasytrade.JRandTest.Tests.BinaryRankTestFor6x8Matrices#setParameters()
	 */
	public void setParameters() {
		testName = "31x31";
		rt = 0;
		no_matrices = 40000;
	}

}