/*
 * Created on 16/03/2005
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

package com.fasteasytrade.JRandTest.Algo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Vector;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Java RSA algorithm implementation.
 * <p>
 * <pre>
 * 2 Sep 2003: Zur Aougav
 * 2 Sep 2003: Copyright (c) 2003 Zur Aougav 
 * 2 Sep 2003: New RSA java class.
 * 2 Sep 2003: Use simple securerandom class to generate p & q primes.
 * 2 Sep 2003: Read and write biginteger to/from streams as object or simple outputstream (with length).
 * 2 Sep 2003: Vector encrypt(byte[] message) does not handle the last bytes properly. Buffer
 *		is filled with 0. Decryption will have 0 (nulls) at end of decoded string.
 * 3 Sep 2003: Add test in main: Shall I compare thee to a summer's day. Shakespeare.
 * 3 Sep 2003: Add save/loadPublicKey and save/loadPrivateKey.
 * 3 Sep 2003: Add -g option: to generate and print keys.
 * 3 Sep 2003: Add -gs option: to generate and save keys in rsapublic.key and rsaprivate.key.
 * 3 Sep 2003: Add encryptFile(infilename,outfilename) and decryptFile(infilename,outfilename).
 * 4 Sep 2003: Add GZIP support.
 *		encryptFileGzip(infilename,outfilename) and decryptFileGzip(infilename,outfilename).
 * 4 Sep 2003: Changed default e=3 to e=65537.
 * 17  Mar 2005: encrypt (0 || random 32 bits || data).
 * </pre>
 * 
 * @author Zur Aougav
 */

public class RSACrypt extends Cipher {
	BigInteger n, d, e;
	int msglen;
	java.util.Random rnd = new java.util.Random();

	/**
	 * Almost null contructor 
	 */
	public RSACrypt() {
		msglen = -1;
	}
	
	/**
	 * Generate public and private keys based on two primes, p and q,
	 * we make public (n, e), and private (n, d).
	 * We discard p and q.
	 */
	public void generateKeys(int bitlen) {
		SecureRandom r = new SecureRandom();
		BigInteger p = new BigInteger(bitlen / 2, 200, r);
		BigInteger q = new BigInteger(bitlen / 2, 200, r);
		n = p.multiply(q);
		BigInteger m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = new BigInteger("65537");
		while(m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
	}
	
	/**
	 * Encrypt one big integer
	 */
	public BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
	}

	/**
	 * Decrypt one big integer
	 */
	public BigInteger decrypt(BigInteger message) {
		return message.modPow(d, n);
	}

	/**
	 * encrypt byte[] and returns vector of bigintegers.
	 */
	public Vector<BigInteger> encrypt(byte[] message) {
		return encrypt(message, message.length);
	}
	
	/**
	 * encrypt byte[] and returns vector of bigintegers.
	 * encrypt just the first mlen bytes.
	 * 
	 * Encrypt:
	 * byte 0 : 0
	 * byte 1 - 4 = random number
	 * byte 5 .. getMessageLen-1 = data
	 */
	public Vector<BigInteger> encrypt(byte[] message, int mlen) {
		if (mlen < 1)
			return null;
		int numMsgs = 1 + (mlen-1) / (getMessageLength() - 5);
		int rest = mlen % (getMessageLength() - 5);
		
		Vector<BigInteger> rslt = new Vector<>();
		byte[] tmp = new byte[getMessageLength()];
		int i,x ;
		int j = 0;	// read from message buffer
		
		for (i = 0; i < numMsgs; i++) {
			Arrays.fill(tmp, 0, getMessageLength(), (byte)0);
			x = rnd.nextInt();
			tmp[1] = (byte) (x >> 24);
			tmp[2] = (byte) (x >> 16);
			tmp[3] = (byte) (x >> 8);
			tmp[4] = (byte) x;
			int k = getMessageLength() - 5;
			if (i+1 == numMsgs && rest > 0)
				k = rest;
        	for (int t = 0; t < k; t++)
        		tmp[t + 5] = message[ j++ ];
			BigInteger v = new BigInteger(tmp);
			rslt.add(encrypt(v));
		}
		return rslt;
	}

	/**
	 * encrypt infile to outfile.
	 */
	public void encryptFile(String infile, String outfile) throws IOException {
		FileInputStream fis = new FileInputStream(infile);
		DataOutputStream out = new DataOutputStream(new FileOutputStream(outfile));
		
		byte[] buffer = new byte[ getMessageLength() - 5 ];
		int len;
		
		while (true) {
			len = fis.read(buffer, 0, buffer.length);
			if (len < 0)		// Found eof?
				break;		// End of encryption
			
			out.writeInt(len);	// write length of data
			Vector<BigInteger> vec = encrypt(buffer);
			if (vec.size() != 1)	// We expect 1 biginteger! 
				throw new IOException("encrypt does not return a biginteger!");
			write(vec.elementAt(0), out);	// write biginteger
		}
		
		out.writeInt(-1);	// write "dummy" EOF - no more bigintegers
		
		out.close();
		fis.close();
	}

	/**
	 * decrypt infile to outfile.
	 */
	public void decryptFile(String infile, String outfile) throws IOException {
		DataInputStream in = new DataInputStream(new FileInputStream(infile));
		FileOutputStream fos = new FileOutputStream(outfile);

		int len;			// real len of data
		BigInteger v;			// read bigintegers from inputfile

		while (true) {
			len = in.readInt();	// read len of data
			//if (len < 0)		// Found our "dummy" EOF?
			if (len < 5)		// Found our "dummy" EOF?
				break;		// End of decryption
			v = read(in);		// read biginteger
			byte[] buffer = decrypt(v).toByteArray();
			//fos.write(buffer, 0,len);	// write just the len data, not more
			fos.write(buffer, 5,len -5); // write just the len data, not more
		}
		fos.close();
		in.close();
	}

	/**
	 * encrypt infile to outfile with compression.
	 */
	public void encryptFileGzip(String infile, String outfile) throws IOException {
		FileInputStream fis = new FileInputStream(infile);
		GZIPOutputStream out = new GZIPOutputStream(new FileOutputStream(outfile));
		
		byte[] buffer = new byte[ getMessageLength() - 5 ];
		int len;
		
		while (true) {
			len = fis.read(buffer, 0, buffer.length);
			if (len < 0)		// Found eof?
				break;		// End of encryption
			
			write(len, out);	// write length of data
			Vector<BigInteger> vec = encrypt(buffer);
			if (vec.size() != 1)	// We expect 1 biginteger! 
				throw new IOException("encrypt does not return a biginteger!");
			write(vec.elementAt(0), out);	// write biginteger
		}
		
		write(-1, out);		// write "dummy" EOF - no more bigintegers
		
		out.close();
		fis.close();
	}

	/*
	 * decrypt compressed infile to outfile.
	 */
	public void decryptFileGzip(String infile, String outfile) throws IOException {
		GZIPInputStream in = new GZIPInputStream(new FileInputStream(infile));
		FileOutputStream fos = new FileOutputStream(outfile);

		int len;			// real len of data
		BigInteger v;			// read bigintegers from inputfile

		while (true) {
			len = readInt(in);	// read len of data
			//if (len < 0)		// Found our "dummy" EOF?
			if (len < 5)		// Found our "dummy" EOF?
				break;		// End of decryption
			v = readBigInteger(in);	// read biginteger
			byte[] buffer = decrypt(v).toByteArray();
			//fos.write(buffer, 0,len);	// write just the len data, not more
			fos.write(buffer, 5,len - 5); // write just the len data, not more
		}
		fos.close();
		in.close();
	}

	
	/**
	 * Returns message length in bytes. Based on n.
	 */
	public int getMessageLength() {
		if (msglen == -1)
			msglen = n.bitLength() / 8;
		return msglen;
	}

	/**
	 * Write one big integer to outputstream, including length.
	 */
	public static void write(BigInteger v, DataOutputStream out) throws IOException {
		byte[] buffer = v.toByteArray();
		int len = buffer.length;
		out.writeInt(len);
		out.write(buffer);
	}

	/**
	 * Write one big integer to outputstream, as java object.
	 */
	public static void write(BigInteger v, ObjectOutputStream out) throws IOException {
		out.writeObject(v);
	}

	/**
	 * Write int to GZIPOutputStream
	 */
	public static void write(int v, GZIPOutputStream out) throws IOException {
		out.write(v>>>24); 		// write Cxxx of v
		out.write(0xff & (v>>>16));	// write xCxx of v
		out.write(0xff & (v>>>8));	// write xxCx of v
		out.write(0xff & v);		// write xxxC of v
	}

	/**
	 * Write one big integer to GZIPoutputstream, including length.
	 */
	public static void write(BigInteger v, GZIPOutputStream out) throws IOException {
		byte[] buffer = v.toByteArray();
		int len = buffer.length;
		write(len, out);
		out.write(buffer);
	}

	/**
	 * Read one big integer from inputstream. First read length, second read bytes to
	 * build the new big integer.
	 */
	public static BigInteger read(DataInputStream in) throws IOException {
		int len = in.readInt();		// read length of bigintegers in bytes
		byte[] buffer = new byte[len];	// alloc array for biginteger
		int k = in.read(buffer, 0, len);// read it
		if (k != len)
			throw new IOException("read biginteger fail. Expect "+len+" bytes. Read "+k+" bytes.");
		return new BigInteger(buffer);
	}

	/**
	 * Read one big integer from inputstream, as java object.
	 */
	public static BigInteger read(ObjectInputStream in) throws IOException, ClassNotFoundException {
		BigInteger v = (BigInteger) in.readObject();
		return v;
	}

	/**
	 * Read int from GZIPinputstream.
	 */
	public static int readInt(GZIPInputStream in) throws IOException {
		int v;
		v = in.read() << 24;	// read first byte
		v |= in.read() << 16;	// read second byte
		v |= in.read() << 8;	// read third byte
		v |= in.read() ;	// read fourth byte
		return v;
	}

	/**
	 * Read one big integer from GZIPinputstream. First read length, second read bytes to
	 * build the new big integer.
	 */
	public static BigInteger readBigInteger(GZIPInputStream in) throws IOException {
		int len = readInt(in);		// read length of bigintegers in bytes
		byte[] buffer = new byte[len];	// alloc array for biginteger
		int k = 0;			// index/location into buffer to read data
		
		// we must read in a loop cause GZIP can bring parts of the data
		while (len > 0) {			// still len to read from GZIP?
			int i = in.read(buffer, k, len);// read next part to fill buffer
			k += i;				// next location in buffer
			len -= i;			// less to read from total/original len
		}
		return new BigInteger(buffer);
	}

	/**
	 * Save public key to file
	 */
	public void savePublicKey(String outfilename) throws IOException {
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(outfilename));
		write(n, out);
		write(e, out);
		out.close();
	}

	/**
	 * Load public key from file
	 */
	public void loadPublicKey(String infilename) throws IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(infilename));
		n  = read(in);
		e  = read(in);
		in.close();
	}

	/**
	 * Save private key to file
	 */
	public void savePrivateKey(String outfilename) throws IOException {
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(outfilename));
		write(n, out);
		write(d, out);
		out.close();
	}

	/**
	 * Load private key from file
	 */
	public void loadPrivateKey(String infilename) throws IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(infilename));
		n  = read(in);
		d  = read(in);
		in.close();
	}

	/**
	 * Just testing RSA class
	 */
	public static void test1 () {
		RSACrypt rsa = new RSACrypt();
		rsa.generateKeys(128);	
		String mymsg = 	"Shall I compare thee to a summer\'s day?\n"+
				"Thou art more lovely and more temperate.\n"+
				"Rough winds do shake the darling buds of May,\n"+
				"And summer\'s lease hath all too short a date.\n"+
				"Sometime too hot the eye of heaven shines,\n"+
				"And often is his gold complexion dimmed,\n"+
				"And every fair from fair sometime declines,\n"+
				"By chance or nature\'s changing course untrimmed;\n"+
				"But thy eternal summer shall not fade\n"+
				"Nor lose possession of that fair thou ow\'st,\n"+
				"Nor shall death brag thou wander\'st in his shade\n"+
				"When in eternal lines to time thou grow\'st.\n"+
				"     So long as men can breathe or eyes can see,\n"+
				"     So long lives this, and this gives life to thee.\n"+
				"\n"+
				"Sonnet 18, William Shakespeare\n"+
				"";
		byte[] mymsgb = mymsg.getBytes();
		Vector<BigInteger> v = rsa.encrypt( mymsgb );
		for (int i = 0; i < v.size(); i++) {
			BigInteger t = v.elementAt(i);
			System.out.print(new String(rsa.decrypt(t).toByteArray()));
		}
	}

	/**
	 * Print usage of main RSA class
	 */
	public static void usage() {
		System.out.println(	"RSACrypt.java class\n"+
					"Copyright (c) 2003 Zur Aougav\n"+
					"Usage: \n"+
					" java RSA -g : to generate and print keys\n"+
					" java RSA -gs : to generate and save keys\n"+
					" java RSA -t : test generate, crypt and decrypt sonnet\n"+
					" java RSA -c infile outfile: load public keys and crypt infile to gzip outfile\n"+
					" java RSA -d infile outfile: load private keys and decrypt gzip infile to outfile\n"+
					" java RSA -cs infile outfile: load public keys and crypt infile to outfile\n"+
					" java RSA -ds infile outfile: load private keys and decrypt infile to outfile" );
	}
	
	/**
	 * Main to test several options of class
	 */
	public static void main (String[] args) {
		int bitlen = 256;
		
		if (args.length == 1) {
			if (args[0].equals("-g")) {		// Generate keys and print
				RSACrypt rsa = new RSACrypt();
				rsa.generateKeys(bitlen);	
				System.out.println("Generate keys:");
				System.out.println("Public key: "+rsa.n.toString()+","+rsa.e.toString());
				System.out.println("Private key: "+rsa.n.toString()+","+rsa.d.toString());
				return;
			}

			if (args[0].equals("-gs")) {		// Generate keys and save
				RSACrypt rsa = new RSACrypt();
				System.out.println("Generate keys...");
				rsa.generateKeys(bitlen);
				try {
					System.out.println("Save public key to rsapublic.key...");
					rsa.savePublicKey("rsapublic.key");
					System.out.println("Save public key to rsaprivate.key...");
					rsa.savePrivateKey("rsaprivate.key");
				} catch (IOException e) {
					System.out.println(e);
				}
				return;
			}

			if (args[0].equals("-t")) {		// Encrypt/Decrypt Sonnet
				test1();
				return;
			}
		}
		
		
		if (args.length == 3 && 
		    (args[0].equals("-c") || args[0].equals("-d") ||
		     args[0].equals("-cs") || args[0].equals("-ds"))) {
			RSACrypt rsa = new RSACrypt();
			try {
				if (args[0].equals("-c") || args[0].equals("-cs")) {// Encrypt?
					System.out.println("Load public key from rsapublic.key...");
					rsa.loadPublicKey("rsapublic.key");
					System.out.println("Encrypt "+args[1]+" into "+args[2]+"...");
					if (args[0].equals("-cs"))
						rsa.encryptFile(args[1], args[2]);
					else
						rsa.encryptFileGzip(args[1], args[2]);
				} else {			// Decrypt
					System.out.println("Load private key from rsaprivate.key...");
					rsa.loadPrivateKey("rsaprivate.key");
					System.out.println("Decrypt "+args[1]+" into "+args[2]+"...");
					if (args[0].equals("-ds"))
						rsa.decryptFile(args[1], args[2]);
					else
						rsa.decryptFileGzip(args[1], args[2]);
				}
			} catch (IOException e) {
				System.out.println(e);
			} catch (ClassNotFoundException ec) {
				System.out.println(ec);
			}
			return;
		} // end encrypt/decrypt
		
		usage();				// unknown parameters
		return;
	} // end main
	
} // end RSA class
	

