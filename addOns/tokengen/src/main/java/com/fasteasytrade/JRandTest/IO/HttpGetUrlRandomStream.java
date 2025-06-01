/*
 * Created on 16/02/2005
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
 * Neither the name of the Zur Aougav nor the names of its contributors may be 
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

import java.io.DataInputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class represents an encrypted or random source HTTP Url source.
 * <p>
 * Data, bytes or int32, are read from url.
 * 
 * @author Zur Aougav
 *  
 */
public class HttpGetUrlRandomStream implements RandomStream {

	boolean open = false;

	DataInputStream infile = null;

	String filename = null; // the url string name

	URL url = null;

	URLConnection con = null;

	int lengthOfData = 0; // length of data return from htpp get request

	int count = 0;

	int countLastRead = 0;

	final int SIZE = 4096 * 4;

	byte[] buffer = new byte[SIZE];

	public HttpGetUrlRandomStream() {
	}

	public HttpGetUrlRandomStream(String s) {
		filename = s;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#getFilename()
	 */
	@Override
	public String getFilename() {
		return filename;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#setFilename(java.lang.String)
	 */
	@Override
	public void setFilename(String s) {
		filename = s;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#isOpen()
	 */
	@Override
	public boolean isOpen() {
		return open;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#openInputStream()
	 */
	@Override
	public boolean openInputStream() throws Exception {
		open = false;
		if (filename == null)
			return false;

		try {
			url = new URL(filename);
			con = url.openConnection();
			con.connect();
			lengthOfData = con.getContentLength();

			/*
			 * debugging: list http headers returned from http get request
			 */
			System.out.println(" headers for url: " + url);
			System.out.println(" lengthOfData = " + lengthOfData);
			Map<String, List<String>> m = con.getHeaderFields();
			Set<String> s = m.keySet();
			Iterator<String> i = s.iterator();
			while (i.hasNext()) {
				String x = i.next();
				Object o = m.get(x);
				String y = null;
				if (o instanceof String)
					y = (String) o;
				else if (o instanceof Collection)
					y = "" + (Collection) o;
				else if (o instanceof Integer)
					y = "" + (Integer) o;
				else
					y = o.getClass().getName();
				System.out.println(" header " + x + " = " + y);
			}

			infile = new DataInputStream(con.getInputStream());
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		open = true;
		count = 0;
		countLastRead = 0;
		return true;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#closeInputStream()
	 */
	@Override
	public boolean closeInputStream() {
		try {
			infile.close();
		} catch (Exception e) {
		}
		open = false;
		return true;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#readByte()
	 */
	@Override
	public byte readByte() throws Exception {
		if (!isOpen())
			return -1;

		try {
			if (count >= countLastRead) {
				count = 0;
				countLastRead = infile.read(buffer);
				if (countLastRead < 0) {
					open = false;
					return -1;
				}
			}
			byte temp = buffer[count];
			count++;
			return temp;
		} catch (Exception e) {
			open = false;
		}

		// passed end of file
		return -1;

	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#readInt()
	 */
	@Override
	public int readInt() throws Exception {
		byte[] b = new byte[4];
		int result = 0;
		for (int i = 0; i < 4; i++) {
			result = (result << 8) | (0xff & readByte());
			if (!isOpen())
				return -1;
		}
		return result;
	}

	/**
	 * @see com.fasteasytrade.JRandTest.IO.RandomStream#readLong()
	 */
	@Override
	public long readLong() throws Exception {
		byte[] b = new byte[8];
		int result = 0;
		for (int i = 0; i < 8; i++) {
			result = (result << 8) | (0xff & readByte());
			if (!isOpen())
				return -1;
		}
		return result;
	}

}