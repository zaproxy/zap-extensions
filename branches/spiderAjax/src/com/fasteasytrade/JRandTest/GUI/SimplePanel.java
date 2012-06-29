/*
 * Created on 12/03/2005
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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;

/**
 * SimplePanel panel has a title and textarea field filling 99% of the panel
 * area.
 * <p>
 * 
 * @author Zur Aougav
 */
public class SimplePanel extends Panel {
	TextArea ta = new TextArea();

	Frame fr;

	SimplePanel(String name, Frame fr) {
		this.fr = fr;
		setLayout(new BorderLayout());
		Label lbl = new Label(name + " test listing");
		lbl.setForeground(Color.white);
		lbl.setBackground(Color.black);
		add("North", lbl);
		ta.setBackground(Color.yellow);
		ta.setFont(new Font("Monospaced", Font.PLAIN, 13));
		add("Center", ta);
	}

	public void setFontSize(int k) {
		ta.setFont(new Font("Monospaced", Font.PLAIN, k));
	}

	public void getFontSize() {
		ta.getFont().getSize();
	}

	public void printf(String s) {
		ta.append(s);
	}

	public void puts(String s) {
		printf(s);
	}

	public void clearText() {
		ta.setText("");
	}

	public void reset() {
		ta.setText("");
	}

	public void setCursor(Cursor c) {
		super.setCursor(c);
		ta.setCursor(c);
	}

}