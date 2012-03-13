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

import java.awt.*;
import java.awt.event.*;

/**
 * MsgBox modal dialog has a title and msg fields/labels. User must click OK
 * button to close window.
 * <p>
 * 
 * @author Zur Aougav
 */
public class MsgBox extends Dialog implements ActionListener {
	/**
	 * parent frame
	 */
	Frame fr;

	/**
	 * title area
	 */
	Label title = new Label();

	/**
	 * msg area
	 */
	Label msg = new Label();

	/**
	 * ok button to exit from modal dialog
	 */
	Button ok = new Button("OK");

	public MsgBox(Frame fr, String msgTitle) {
		super(fr, msgTitle, true); // make it modal

		this.fr = fr;

		setLayout(new GridLayout(0, 1));

		setTitle(msgTitle);
		title.setForeground(Color.white);
		title.setBackground(Color.black);
		add(title);

		add(new Label(""));

		add(msg);

		add(new Label(""));

		ok.addActionListener(this);

		add(ok);

		pack();
	}

	/**
	 * set title label. Usually with "Error" or "Warning".
	 */
	public void setTitle(String s) {
		title.setText(s);
		pack();
	}

	/**
	 * set msg text
	 * 
	 * @param s actual msg
	 */
	public void setMsg(String s) {
		msg.setText(s);
		pack();
	}

	/**
	 * handle the OK button to close / hide message window
	 */
	public void actionPerformed(ActionEvent evt) {
		String arg = (String) evt.getActionCommand();

		if (arg.equals("OK")) {
			hide();
			return;
		}
	}
}