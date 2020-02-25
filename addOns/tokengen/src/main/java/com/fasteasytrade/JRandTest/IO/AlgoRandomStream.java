/*
 * Created on 06/03/2005
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
 * Interface to Algorithm as random stream
 * 
 * @author Zur Aougav
 *  
 */
public interface AlgoRandomStream extends RandomStream {

	/**
	 * set up length and new arrays to public and private keys
	 * <p>
	 * will be implemented by each algorithm
	 */
	public void setupKeys();

	/**
	 * Set public or symetric key to algorithm from file
	 * 
	 * @param f
	 *            file name with public or symetric key
	 */
	public void setPublicKeyFromFile(String f);

	/**
	 * Set public or symetric key to algorithm
	 * 
	 * @param k
	 *            byte array of public or symetric key
	 */
	public void setPublicKey(byte[] k);

	/**
	 * Set private key, if any, to algorithm from file
	 * 
	 * @param f
	 *            file name with private key
	 */
	public void setPrivateKeyFromFile(String f);

	/**
	 * Set private key, if any, to algorithm
	 * 
	 * @param k
	 *            byte array of private key
	 */
	public void setPrivateKey(byte[] k);

	/**
	 * Setup before encryption
	 */
	public void setup();
}