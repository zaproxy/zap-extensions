package org.zaproxy.zap.extension.exportReport.Utility;

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
 * This file is based on the Paros code file ReportLastScan.java
 */

import java.awt.*;
import java.awt.font.*;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.imageio.ImageIO;
import javax.swing.*;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	SharedFunctions.java 
 * DESC			:	Methods that are used frequently to create swing components, etc.
 * CREATED ON	:	MARCH 10TH, 2016
 * CURRENT VER	:	V1.0
 * SOURCE		:	https://github.com/JordanGS/workspace/tree/master/zap-extensions/src/org/zaproxy/zap/extension/exportReport
 */

/* 
 * MODIFED BY	:	<NAME> - <GIT USER>
 * MOD DATE		:	
 * MOD VERSION	:	<VERSION OF PLUGIN>
 * MOD DESC		:	
 */

public class SharedFunctions
{

	public SharedFunctions()
	{
		// TODO Auto-generated constructor stub
	}

	public static String getCurrentTimeStamp()
	{
		SimpleDateFormat date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z(Z)");
		Date now = new Date();
		String strDate = date.format(now);
		// System.out.println(strDate);
		return strDate;
	}

	public static Font getTitleFont()
	{
		Map<TextAttribute, Integer> fontAttributes = new HashMap<TextAttribute, Integer>();
		fontAttributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
		return new Font("Arial", Font.BOLD, 30).deriveFont(fontAttributes);
	}

	public static Font getLabelFont()
	{
		return new Font("Arial", Font.BOLD, 14);
	}

	public static void allignLabelTop(JLabel lbl)
	{
		lbl.setVerticalAlignment(JLabel.TOP);
		lbl.setVerticalTextPosition(JLabel.TOP);
		lbl.setBorder(BorderFactory.createEmptyBorder(3 /* top */, 0, 0, 0));
	}

	public static JLabel createLabel(JPanel pnl, JLabel lbl, String str, Font font)
	{
		lbl = new JLabel(str, JLabel.TRAILING);
		lbl.setFont(font);
		pnl.add(lbl);
		return lbl;
	}

	public static JButton createImageButton(JButton btn, String strImg)
	{
		btn = new JButton();
		Image img = null;
		try
		{
			img = ImageIO.read(new File(strImg));
		}
		catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		btn.setIcon(new ImageIcon(img));
		btn.setPreferredSize(new Dimension(20, 20));
		return btn;
	}

	public static JFormattedTextField createDateField(JPanel pnl, JFormattedTextField txt, String str, String tip)
	{
		SimpleDateFormat format = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z(Z)");
		txt = new JFormattedTextField(format);
		txt.setText(str);
		txt.setToolTipText(tip);
		pnl.add(txt);
		return txt;
	}

	public static JTextField createTextField(JPanel pnl, JTextField txt, String str, String tip, Boolean bool,
			int limit)
	{
		txt = new JTextField();
		if (limit > -1)
		{
			txt.setDocument(new JTextFieldLimit(limit));
		}
		txt.setText(str);
		txt.setEditable(bool);
		txt.setToolTipText(tip);
		pnl.add(txt);
		return txt;
	}

	public static JTextArea createTextArea(JTextArea txt, int rows, int cols, String tip, int limit)
	{
		txt = new JTextArea(rows, cols);
		if (limit > -1)
		{
			txt.setDocument(new JTextFieldLimit(limit));
		}
		txt.setToolTipText(tip);
		txt.setLineWrap(true);
		txt.setWrapStyleWord(true);
		return txt;
	}

	public static JComboBox<Object> createComboBox(JPanel pnl, JComboBox<Object> typeList, ArrayList<String> list)
	{
		typeList = new JComboBox<>(list.toArray());
		typeList.setSelectedIndex(0);
		pnl.add(typeList);
		return typeList;
	}

	public static String[] appendToArray(ArrayList<String> list, int count, int max)
	{
		count++;
		String[] compile = new String[list.size()];
		for (int i = 0; i < compile.length; i++)
		{
			String temp = Integer.toString(count);
			for (int j = temp.length(); j < (Integer.toString(max)).length(); j++)
			{
				compile[i] = ((compile[i] == null) ? "0" : compile[i] + "0");
			}
			compile[i] = ((compile[i] == null) ? count + ". " + list.get(i) : compile[i] + count + ". " + list.get(i));
			count++;
		}
		return compile;

	}

	public static SpringLayout setupConstraints(SpringLayout sl, JPanel content, JPanel container, int[] pad)
	{
		sl.putConstraint(SpringLayout.NORTH, content, pad[0], SpringLayout.NORTH, container);
		sl.putConstraint(SpringLayout.WEST, content, pad[1], SpringLayout.WEST, container);
		sl.putConstraint(SpringLayout.SOUTH, content, pad[2], SpringLayout.NORTH, container);
		sl.putConstraint(SpringLayout.EAST, content, pad[3], SpringLayout.WEST, container);
		return sl;
	}
}