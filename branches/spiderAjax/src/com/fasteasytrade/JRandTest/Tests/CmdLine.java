/*
 * Created on 19/02/2005
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

import java.io.*;
import java.util.*;

import com.fasteasytrade.JRandTest.IO.*;

/**
 * Commnad line class to read from console / end-user the filename /
 * algorithmname and testname to be executed.
 * <p>
 * Generally, we will try to keep similar functions and options as in Gui class.
 * 
 * @author Zur Aougav
 */
public class CmdLine {

	String[] cardNames = { "Monte Carlo", "Count 1 Bit", "Count 2 Bits" };

	String[] classNames = { "MonteCarlo", "Count1Bit", "Count2Bits" };

	String[] algoNames = { "None", "ARC4", "MT19937", "BlowFish", "RSA",
			"JavaRandom", "JavaSecuredRandom" };

	String[] algoClassNames = { "None", "ARC4", "MT19937", "BlowFish", "RSA",
			"JavaRandom", "JavaSecuredRandom" };

	// classes are included here just to ease compile... not used anywhere!
	Run r1;

	Count1Bit r2;

	Count2Bits r3;

	Count3Bits r4;

	Count4Bits r5;

	Count8Bits r6;

	Count16Bits r7;

	MonteCarlo r8;

	Squeeze r9;

	MinimumDistance r10;

	CountThe1s r11;

	CountThe1sSpecificBytes r12;

	BirthdaySpacings r13;

	BinaryRankTestFor6x8Matrices r14;

	BinaryRankTestFor31x31Matrices r15;

	BinaryRankTestFor32x32Matrices r16;

	Overlapping20TuplesBitstream r17;

	OverlappingPairsSparseOccupancy r18;

	OverlappingQuadruplesSparseOccupancy r19;

	DNA r20;

	/**
	 * print copyrights to console.
	 *  
	 */
	public static void printCopyrights() {
		System.out
				.println("JRandTest (C) Zur Aougav <aougav@hotmail.com>, 2005");
	}

	/**
	 * read list of tests from property file named alltests.txt.
	 * <p>
	 * Property file contains:
	 * <p>
	 * shortname=classname
	 * <p>
	 * where shortname will be displayed toend user in GUI window.
	 * <p>
	 * classname is the real class name of the test to be laoded dynamically and
	 * run (as Base interface).
	 *  
	 */
	private Vector loadPropFile(String fn) {
		Vector v = new Vector(); // to keep correct strings of lines
		String line;
		ResourceBundle rb = null;

		try {
			System.out.println("load " + fn + "...");
			BufferedReader b = new BufferedReader(new InputStreamReader(
					new FileInputStream(fn)));

			while ((line = b.readLine()) != null) {
				line = line.trim();

				/*
				 * if "=" not in line... skip it
				 */
				if (line.length() < 3 || line.startsWith("#")
						|| line.startsWith(";") || line.indexOf("=") < 0)
					continue;
				System.out.println("add : /" + line + "/");
				v.add(line);
			}

			b.close();
		} catch (Exception e) {
			System.out.println(e);
		}

		int vsize = v.size();

		if (vsize == 0)
			try {
				System.out.println("load resource bundle...");
				rb = ResourceBundle.getBundle(fn);
				if (rb != null) {
					Enumeration e = rb.getKeys();
					while (e.hasMoreElements()) {
						String key = (String) e.nextElement();
						String value = rb.getString(key);
						line = key + "=" + value;
						v.add(line);
					}
				}
				vsize = v.size();
			} catch (Exception e) {
			}

		if (vsize == 0) // no tests?
			return null;

		String[] cardNames = new String[vsize];
		String[] classNames = new String[vsize];
		String c, n;
		int i;

		for (int j = 0; j < vsize; j++) {
			line = (String) v.elementAt(j);
			i = line.indexOf("=");
			n = line.substring(0, i).trim();
			c = line.substring(i + 1).trim();
			cardNames[j] = n;
			classNames[j] = c;
		}

		v = new Vector(2);
		v.add(cardNames);
		v.add(classNames);
		return v;
	}

	/**
	 * Simple session: <br>
	 * 1. get input filename/algorithm for all tests (or "exit") <br>
	 * 2. repeat till "exit" <br>
	 * 2.1 display list of tests <br>
	 * 2.2 get requested test number <br>
	 * 2.3 run the test on the input file <br>
	 * 
	 * @param args
	 *            not used.
	 * @throws Exception
	 *             generally are grabbed, but some I/O Exceptions are thrown.
	 */
	public void runCmd(String[] args) throws Exception {
		printCopyrights();

		/**
		 * load algorithms' names
		 */
		Vector tvec = loadPropFile("allalgos.txt");
		if (tvec != null) {
			algoNames = (String[]) tvec.elementAt(0);
			algoClassNames = (String[]) tvec.elementAt(1);
		}

		/**
		 * load tests' names
		 */
		tvec = loadPropFile("alltests.txt");
		if (tvec != null) {
			cardNames = (String[]) tvec.elementAt(0);
			classNames = (String[]) tvec.elementAt(1);
		}

		String line = null;
		BufferedReader dis = new BufferedReader(
				new InputStreamReader(System.in));

		String filename = null;
		File file;

		int algoNumber = -1; // -1 is None

		do {

			/*
			 * select algorithm, if any
			 */
			do {
				System.out
						.println("Specify algorithm number to be run on input file (\"none\" or \"exit\" to exit):");
				System.out.println(" 0. None");
				for (int i = 0; i < algoNames.length; i++)
					if ((i + 1) < 10)
						System.out.println(" " + (i + 1) + ". " + algoNames[i]);
					else
						System.out.println("" + (i + 1) + ". " + algoNames[i]);

				line = dis.readLine().trim(); // take input from end-user

				if (line == null)
					return;

				if (line.length() == 0)
					continue;

				if ("exit".equals(line.toLowerCase()) || "quit".equals(line.toLowerCase())) { // exit?
					System.out.println("Byte.");
					return;
				}

				/*
				 * no algorithm?
				 */
				if (line.startsWith("None") || line.startsWith("none")) {
					algoNumber = -1;
					break;
				}

				try {
					algoNumber = Integer.parseInt(line) - 1;
					if (-1 <= algoNumber && algoNumber < algoNames.length)
						break;
				} catch (Exception e) {
					System.out.println("Error: " + e);
				}
			} while (true);

			do {
				System.out
						.println("Specify filename (\"none\" or \"exit\" to exit):");

				line = dis.readLine().trim(); // take input from end-user

				if (line == null)
					return;

				if (line.length() == 0)
					continue;

				if ("exit".equals(line.toLowerCase()) || "quit".equals(line.toLowerCase())) { // exit?
					System.out.println("Byte.");
					return;
				}

				filename = line;

				/*
				 * no file?
				 */
				if (filename.startsWith("None") || filename.startsWith("none")) {
					filename = null;
					break;
				}

				try {
					/*
					 * is it a file?
					 */
					file = new File(filename);
					if (file.exists())
						break;
					else
						System.out.println("File "+filename+" not found.");
					
				} catch (Exception e) {
					System.out.println("Error: " + e);
				}
			} while (true);

			if (filename != null || algoNumber > -1)
				break;
			else
				System.out
						.println("You must specify algorithm name and/or filename");
		} while (true);

		/**
		 * At this point we have algorithm name or filename (or both)
		 */

		/**
		 * run several tests on the same input file
		 */
		do {
			int testNumber = -1;

			do {
				System.out
						.println("Specify test number to be run on algorithm / input file (or \"exit\" to exit):");
				for (int i = 0; i < cardNames.length; i++)
					if ((i + 1) < 10)
						System.out.println(" " + (i + 1) + ". " + cardNames[i]);
					else
						System.out.println("" + (i + 1) + ". " + cardNames[i]);

				line = dis.readLine().trim(); // take input from end-user

				if (line == null)
					return;

				if (line.length() == 0)
					continue;

				if ("exit".equals(line.toLowerCase()) || "quit".equals(line.toLowerCase())) { // exit?
					System.out.println("Byte.");
					return;
				}

				try {
					testNumber = Integer.parseInt(line) - 1;
					if (0 <= testNumber && testNumber < cardNames.length)
						break;
				} catch (Exception e) {
					System.out.println("Error: " + e);
				}
			} while (true);

			// run test...
			String classname = classNames[testNumber];
			Base ob = null;
			try {
				ob = (Base) Class.forName(classname).newInstance();
			} catch (Exception e) {
			}

			if (ob == null)
				try {
					classname = this.getClass().getPackage().getName() + "."
							+ classNames[testNumber];
					ob = (Base) Class.forName(classname).newInstance();
				} catch (Exception e) {
					e.printStackTrace();
					System.out.println(e);
					return;
				}

			if (ob == null)
				return;

			String algoname = "";
			if (filename == null)
				filename = "";

			try {
				if (algoNumber > -1) {
					algoname = algoNames[algoNumber];
					AlgoRandomStream rs = null;
					classname = algoClassNames[algoNumber];
					String algoclassname = algoClassNames[algoNumber];
					System.out.println("algorithm: " + algoname + " from "
							+ classname);
					try {
						rs = (AlgoRandomStream) Class.forName(classname)
								.newInstance();
					} catch (Exception e) {
					}
					if (rs == null) {
						classname = "com.fasteasytrade.JRandTest.Algo."
								+ algoclassname;
						System.out.println("algorithm: " + algoname + " from "
								+ classname);
						rs = (AlgoRandomStream) Class.forName(classname)
								.newInstance();
					}
					/*
					 * prepare keys
					 */
					rs.setupKeys();

					/*
					 * set input file to algorthm, if any
					 */
					if (filename != null && filename.length() > 0)
						rs.setFilename(filename);

					/*
					 * init algorithm
					 */
					//rs.setup();
					/*
					 * make algo as input to test
					 */
					ob.registerInput(rs);

				} else if (filename.toUpperCase().startsWith("HTTP://"))
					ob.registerInput(new HttpGetUrlRandomStream(filename));
				else
					ob.registerInput(new FileRandomStream(filename));

				/*
				 * run test!
				 */
				ob.help();
				ob.test(algoname + " @ " + filename);

			} catch (Exception e) {
				e.printStackTrace();
				ob.printf("" + e);
			}

		} while (true); // run several tests on the the same algorithm / input file
	}

	public static void main(String[] args) {
		CmdLine cl = new CmdLine();

		try {
			cl.runCmd(args);
		} catch (Exception e) {
			System.out.println("Sorry. Error while processing CmdLine.");
			e.printStackTrace();
			System.out.println(e);
		}
	}
}