/*
 * Created on 05/02/2005
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

package com.fasteasytrade.JRandTest.IO;

/**
 * RandomStream interface represen stream of data to be checked by the different
 * tests. The interface will be implemented by real classes to read data from
 * files, external devices, web urls or algorithms.
 * 
 * @author Zur Aougav
 */
public interface RandomStream {
	/**
	 * check if RandomStream is open
	 * 
	 * @return true if open (still data in stream), else flase
	 */
	public boolean isOpen();

	/**
	 * set file name to be processed. this file is the raw data to be read, or
	 * the input file processed by algorithm.
	 * 
	 * @return true if open (still data in stream), else flase
	 */
	public void setFilename(String s);

	/**
	 * get the file name to be processed. this file is the raw data to be read,
	 * or the input file processed by algorithm.
	 * 
	 * @return string null if missing, else the filename from setFilename.
	 */
	public String getFilename();

	/**
	 * open the input stream.
	 * 
	 * @return boolean true for success, else false.
	 * @throws Exception -
	 *             Usually IOException.
	 */
	abstract public boolean openInputStream() throws Exception;

	/**
	 * close the input stream.
	 * 
	 * @return boolean true for success, else false.
	 */
	abstract public boolean closeInputStream();

	/**
	 * read one byte from a file.
	 * <p>
	 * first time ( if !isOpen() ) open file/stream, and return byte
	 * <p>
	 * at end of file close stream and returns -1
	 * <p>
	 * 
	 * @return byte read form stream, -1 if passed end of file
	 */
	public byte readByte() throws Exception;

	/**
	 * Processing is similar to readByte.
	 * <p>
	 * 
	 * @return int (32 bits, 4 bytes) read form stream, -1 if passed end of file
	 */
	public int readInt() throws Exception;

	/**
	 * Processing is similar to readByte.
	 * <p>
	 * 
	 * @return long (64 bits, 8 bytes) read form stream, -1 if passed end of
	 *         file
	 */
	public long readLong() throws Exception;

}