/*
 * Created on 04/02/2005
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

package com.fasteasytrade.JRandTest.GUI;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import com.fasteasytrade.JRandTest.IO.*;
import com.fasteasytrade.JRandTest.Tests.*;

/**
 * Main Java application to run randomness tests on files and algorithms.
 * <p>
 * 
 * @author Zur Aougav
 */
public class Gui extends Frame implements ActionListener, ItemListener {

	private Panel cards;

	private Panel tabs;

	private CardLayout layout;

	FileDialog fd = new FileDialog(this, "Select file...", FileDialog.LOAD);

	AboutDialog ad = new AboutDialog(this, true);

	MsgBox msgbox = new MsgBox(this, "JRandTest"); // show user modal dialog msg

	String filename = null;

	String publicKeyFilename = null;

	String privateKeyFilename = null;

	Label tLabel;

	TextField filenameLabel;

	TextField publicKeyFilenameLabel;

	TextField privateKeyFilenameLabel;

	String[] cardNames = { "Monte Carlo", "Count 1 Bit", "Count 2 Bits" };

	String[] classNames = { "MonteCarlo", "Count1Bit", "Count2Bits" };

	String[] algoNames = { "None", "ARC4", "MT19937", "BlowFish", "RSA",
			"JavaRandom", "JavaSecuredRandom" };

	String[] algoClassNames = { "None", "ARC4", "MT19937", "BlowFish", "RSA",
			"JavaRandom", "JavaSecuredRandom" };

	/*
	 * vector vcSD will contains SimplePanel for each test...
	 */
	Vector vecSP = new Vector();

	int currentCard = 0; // index to current num of card shown on cardLayout

	int numCards = 0; // total numk of cards

	String algoname = null; // algorithm name to run as source of random data

	String algoclassname = null;

	java.awt.Choice algolist = null;

	java.awt.Choice testslist = null;

	int fontSize = 13;

	int fontSizeMin = 11;

	int fontSizeMax = 21;

	Cursor waitCursor = Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR);

	Cursor defaultCursor = Cursor.getDefaultCursor();

	/*
	 * classes are included here just to ease compile... not used anywhere!
	 */
	/*
	 * Run r1;
	 * 
	 * Count1Bit r2;
	 * 
	 * Count2Bits r3;
	 * 
	 * Count3Bits r4;
	 * 
	 * Count4Bits r5;
	 * 
	 * Count8Bits r6;
	 * 
	 * Count16Bits r7;
	 * 
	 * MonteCarlo r8;
	 * 
	 * Squeeze r9;
	 * 
	 * MinimumDistance r10;
	 * 
	 * CountThe1s r11;
	 * 
	 * CountThe1sSpecificBytes r12;
	 * 
	 * BirthdaySpacings r13;
	 * 
	 * BinaryRankTestFor6x8Matrices r14;
	 * 
	 * BinaryRankTestFor31x31Matrices r15;
	 * 
	 * BinaryRankTestFor32x32Matrices r16;
	 * 
	 * Overlapping20TuplesBitstream r17;
	 * 
	 * OverlappingPairsSparseOccupancy r18;
	 * 
	 * OverlappingQuadruplesSparseOccupancy r19;
	 * 
	 * DNA r20;
	 */

	/**
	 * constructor to gui application. Builds all frames, modal windows, panels
	 * and lists.
	 */
	public Gui() {
		super("JRandTest"); // Frame title

		Panel title = new Panel(new BorderLayout());
		Panel v = new Panel(new GridLayout(0, 2));
		Panel toptabs = new Panel();

		tLabel = new Label("Java Randomness Tests");
		tLabel.setFont(new Font("Monospaced", Font.ITALIC | Font.BOLD, 20));
		toptabs.add(tLabel);

		tLabel = new Label("Copyright (c) 2005, Zur Aougav   ^_^");
		tLabel.setFont(new Font("TimesNewRoman", 0, 14));
		toptabs.add(tLabel);

		title.add(toptabs, "North");

		toptabs = new Panel();

		toptabs.add(new Label("Algorithm:"));
		v.add(toptabs);
		toptabs = new Panel();

		Vector tvec = loadPropFile("allalgos.txt");
		if (tvec != null) {
			algoNames = (String[]) tvec.elementAt(0);
			algoClassNames = (String[]) tvec.elementAt(1);
		}

		algolist = new java.awt.Choice();
		algolist.add("None");
		for (int i = 0; i < algoNames.length; i++) {
			if (!"None".equals(algoNames[i]))
				algolist.add(algoNames[i]);
		}
		algolist.addItemListener(this);
		toptabs.add(algolist);
		v.add(toptabs);
		toptabs = new Panel();

		int tfSize = 45;
		addButton("Public key file...", toptabs);
		v.add(toptabs);
		toptabs = new Panel();
		publicKeyFilenameLabel = new TextField(tfSize);
		toptabs.add(publicKeyFilenameLabel);
		v.add(toptabs);
		toptabs = new Panel();

		addButton("Private key file...", toptabs);
		v.add(toptabs);
		toptabs = new Panel();
		privateKeyFilenameLabel = new TextField(tfSize);
		toptabs.add(privateKeyFilenameLabel);
		v.add(toptabs);
		toptabs = new Panel();

		addButton("File...", toptabs);
		v.add(toptabs);
		toptabs = new Panel();
		filenameLabel = new TextField(tfSize);
		toptabs.add(filenameLabel);

		v.add(toptabs);
		toptabs = new Panel();

		addButton("<<", toptabs, 0);
		addButton("<", toptabs, 0);
		addButton("Run...", toptabs, 0);
		addButton(">", toptabs, 0);
		addButton(">>", toptabs, 0);
		v.add(toptabs);
		toptabs = new Panel();

		tvec = loadPropFile("alltests.txt");
		if (tvec != null) {
			cardNames = (String[]) tvec.elementAt(0);
			classNames = (String[]) tvec.elementAt(1);
		}

		numCards = cardNames.length;
		testslist = new java.awt.Choice();
		for (int i = 0; i < numCards; i++)
			testslist.add(cardNames[i]);
		testslist.addItemListener(this);
		toptabs.add(testslist);
		v.add(toptabs);
		toptabs = new Panel();

		title.add(v, "Center");
		add(title, "North");

		cards = new Panel();
		layout = new CardLayout();
		cards.setLayout(layout);

		SimplePanel sd;
		for (int i = 0; i < numCards; i++) {
			cards.add(sd = new SimplePanel(cardNames[i], this), cardNames[i]);
			vecSP.add(sd);
		}

		add(cards, "Center");

		MenuBar mb = new MenuBar();
		Menu m;
		MenuItem mi;

		m = new Menu("File");
		mb.add(m);
		mi = new MenuItem("Public key file...");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("Private key file...");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("File...");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("Run...");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("Exit");
		mi.addActionListener(this);
		m.add(mi);

		m = new Menu("Edit");
		mb.add(m);
		for (int i = fontSizeMin; i <= fontSizeMax; i += 2) {
			mi = new MenuItem("Font size " + i);
			mi.addActionListener(this);
			m.add(mi);
		}
		mi = new MenuItem("Clear");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("Clear All");
		mi.addActionListener(this);
		m.add(mi);

		m = new Menu("Help");
		mb.setHelpMenu(m);
		mi = new MenuItem("Homepage");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("Javadoc");
		mi.addActionListener(this);
		m.add(mi);
		mi = new MenuItem("About");
		mi.addActionListener(this);
		m.add(mi);

		setMenuBar(mb);
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
	 * make new button and insert it into a panel
	 * 
	 * @param name
	 *            label of button
	 * @param p
	 *            panel contains new button
	 */
	public void addButton(String name, Panel p) {
		SimpleButton b = new SimpleButton(name);
		b.addActionListener(this);
		p.add(b);
	}

	/**
	 * make new button, with specified size, and insert it into a panel
	 * 
	 * @param name
	 *            label of button
	 * @param p
	 *            panel contains new button
	 * @param width
	 *            of button
	 */
	public void addButton(String name, Panel p, int width) {
		SimpleButton b = new SimpleButton(name, width);
		b.addActionListener(this);
		p.add(b);
	}

	/**
	 * make new button in defualt panel, tabs panel
	 * 
	 * @param name
	 *            label of button
	 */
	public void addButton(String name) {
		addButton(name, tabs);
	}

	public void addRadioButton(String name, Panel p, CheckboxGroup cg) {
		Checkbox b = new Checkbox(name, false, cg);
		b.addItemListener(this);
		p.add(b);
	}

	public void addRadioButton(String name, CheckboxGroup cg) {
		addRadioButton(name, tabs, cg);
	}

	public void itemStateChanged(ItemEvent e) {
		Object ob = e.getSource();

		/*
		 * Checbox is currently not used... keep code :-)
		 */
		if (ob instanceof Checkbox) {
			//		get name of radio button
			String arg = (String) e.getItem();

			//		show related card to radio button
			layout.show(cards, arg);

			//		set currentCrad to card shown
			for (int i = 0; i < numCards; i++)
				if (cardNames[i].equals(arg)) {
					currentCard = i;
					break;
				}
			return;
		}

		if (ob == algolist) {
			int k = algolist.getSelectedIndex();
			algoname = algolist.getSelectedItem();
			algoclassname = null;
			if ("None".equals(algoname))
				algoname = null;
			else
				algoclassname = algoClassNames[k - 1];

			return;
		}

		if (ob == testslist) {
			int k = testslist.getSelectedIndex();
			layout.show(cards, cardNames[k]);
			currentCard = k;
			return;
		}
	}

	/**
	 * main method logic to process click/typed information.
	 * <p>
	 * buttons specify test/file/algorithm.
	 * <p>
	 * "run" buttons will load test class dynamically and invoked with setting
	 * TextArea as OutputDestination, and filename/algrorithm as input random
	 * stream.
	 */
	public void actionPerformed(ActionEvent evt) {

		System.gc();

		String arg = (String) evt.getActionCommand();

		if (arg.equals("Homepage")) {
			String s = "cmd /c \"start http://jrandtest.sourceforge.net\""; // XP/NT/2000

			String osname = System.getProperty("os.name");
			if (osname.startsWith("Windows 9")
					|| osname.startsWith("Windows M"))
				s = "start http://jrandtest.sourceforge.net"; // 95/98/ME

			try {
				Runtime.getRuntime().exec(s);
			} catch (Exception e) {
			}
			return;
		}

		if (arg.equals("Javadoc")) {
			String s = "cmd /c \"start javadoc\\index.html\""; // XP/NT/2000

			String osname = System.getProperty("os.name");
			if (osname.startsWith("Windows 9")
					|| osname.startsWith("Windows M"))
				s = "start javadoc\\index.html"; // 95/98/ME

			try {
				Runtime.getRuntime().exec(s);
			} catch (Exception e) {
			}
			return;
		}

		if (arg.equals("About")) {
			ad.show();
			return;
		}

		if (arg.equals("File...")) {
			fd.show();
			if (fd.getFile() == null) // no file selected?
				return;
			filename = fd.getDirectory() + fd.getFile();
			filenameLabel.setText(filename);
			return;
		}

		if (arg.equals("Public key file...")) {
			fd.show();
			if (fd.getFile() == null) // no file selected?
				return;
			publicKeyFilename = fd.getDirectory() + fd.getFile();
			publicKeyFilenameLabel.setText(publicKeyFilename);
			return;
		}

		if (arg.equals("Private key file...")) {
			fd.show();
			if (fd.getFile() == null) // no file selected?
				return;
			privateKeyFilename = fd.getDirectory() + fd.getFile();
			privateKeyFilenameLabel.setText(privateKeyFilename);
			return;
		}

		if (arg.equals("Exit")) {
			System.exit(0);
			return;
		}

		if (arg.startsWith("Font size")) {
			int i = 13;
			try {
				i = Integer.parseInt(arg.substring(10));
			} catch (Exception e) {
				System.out.println(arg.substring(10) + "/: " + e);
			}

			SimplePanel sd;
			for (int k = 0; k < vecSP.size(); k++) {
				sd = (SimplePanel) vecSP.elementAt(k);
				sd.setFontSize(i);
			}
			return;
		}

		if (arg.equals("<<")) {
			currentCard = 0;
			layout.first(cards);
			testslist.select(currentCard);
			return;
		}
		if (arg.equals("<")) {
			currentCard--;
			if (currentCard < 0)
				currentCard = numCards - 1;
			layout.previous(cards);
			testslist.select(currentCard);
			return;
		}
		if (arg.equals(">")) {
			currentCard = (currentCard + 1) % numCards;
			layout.next(cards);
			testslist.select(currentCard);
			return;
		}
		if (arg.equals(">>")) {
			currentCard = numCards - 1;
			layout.last(cards);
			testslist.select(currentCard);
			return;
		}

		if (arg.equals("Clear")) {
			SimplePanel sd = (SimplePanel) vecSP.elementAt(currentCard);
			sd.clearText();
			return;
		}

		if (arg.equals("Clear All")) {
			SimplePanel sd;
			for (int k = 0; k < vecSP.size(); k++) {
				sd = (SimplePanel) vecSP.elementAt(k);
				sd.clearText();
			}
			return;
		}

		if (arg.equals("Run...")
				&& (filenameLabel.getText().trim().length() > 0 || algoname != null)) {
			filename = filenameLabel.getText().trim();
			SimplePanel sd = (SimplePanel) vecSP.elementAt(currentCard);
			sd.printf("\n-------------------------------------\n");
			String classname = classNames[currentCard];
			Base ob = null;
			try {
				ob = (Base) Class.forName(classname).newInstance();
			} catch (Exception e) {
			}

			if (ob == null)
				try {
					classname = this.getClass().getPackage().getName() + "."
							+ classNames[currentCard];
					ob = (Base) Class.forName(classname).newInstance();
				} catch (Exception e) {
					e.printStackTrace();
					System.out.println(e);
					return;
				}

			if (ob == null)
				return;

			try {
				if (algoname != null) {
					AlgoRandomStream rs = null;
					classname = algoclassname;
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
					 * set public key, if any
					 */
					publicKeyFilename = publicKeyFilenameLabel.getText();
					if (publicKeyFilename != null
							&& publicKeyFilename.trim().length() > 0)
						rs.setPublicKeyFromFile(publicKeyFilename);
					/*
					 * set private key, if any
					 */
					privateKeyFilename = privateKeyFilenameLabel.getText();
					if (privateKeyFilename != null
							&& privateKeyFilename.trim().length() > 0)
						rs.setPublicKeyFromFile(privateKeyFilename);

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
				 * connect text area as output destination to test
				 */
				ob.addOutputDestination(new TextareaOutputDestination(sd.ta));

				//ob.help();

				/*
				 * run test!
				 */
				setCursor(waitCursor);
				sd.setCursor(waitCursor);

				ob.test(algoname + " @ " + filename);

				setCursor(defaultCursor);
				sd.setCursor(defaultCursor);

			} catch (Exception e) {
				e.printStackTrace();
				ob.printf("" + e);
			}
			return;
		}

		if (arg.equals("Run...")) {
			msgbox.setTitle("Error:");
			msgbox.setMsg("Specify algorithm or file or algorithm&file.");
			msgbox.show();
		}
	}

	public static void main(String[] args) {
		Gui g = new Gui();
		/*
		 * To properly close the window, create a WindowListener using an
		 * anonymous adapter class.
		 */
		WindowListener listener = new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			}
		};
		/*
		 * and add it to the frame.
		 */
		g.addWindowListener(listener);
		g.setSize(600, 600);
		g.show();
	}
}