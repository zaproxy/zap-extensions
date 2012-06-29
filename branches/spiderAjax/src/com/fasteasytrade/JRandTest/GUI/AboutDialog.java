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

package com.fasteasytrade.JRandTest.GUI;

import java.awt.*;

/**
 * Display about modal window.
 * <p>
 * @author Zur Aougav
 */
public class AboutDialog extends Dialog
{
	Button okButton;
	Label titlePage;
	VWrappingLabel description;

	public AboutDialog(Frame parent, String title, boolean modal)
	{
		this(parent, modal);
		setTitle(title);
	}

	public AboutDialog(Frame parent, boolean modal)
	{

		super(parent, modal);

		setLayout(null);
		addNotify();
		resize(
			insets().left + insets().right + 417,
			insets().top + insets().bottom + 429);

		okButton = new Button("OK");
		okButton.reshape(insets().left + 144, insets().top + 384, 66, 27);
		add(okButton);

		titlePage = new Label();
		titlePage.reshape(insets().left + 24, insets().top + 24, 312, 36);
		titlePage.setFont(new Font("TimesRoman", Font.BOLD | Font.ITALIC, 24));
		add(titlePage);
		titlePage.setText("About JRandTest...");

		description = new VWrappingLabel();
		description.setVAlignStyle(250);
		description.reshape(insets().left + 24, insets().top + 68, 360, 305);
		description.setFont(new Font("TimesRoman", Font.BOLD, 14));
		add(description);

		String s = "The JRandTest was created by Zur Aougav.";
		s += "\n\nIt was created as a part of cryptography and cryptanalysis project.";
		s += "\n\nThis project's purpose is to help students";
		s += " and professionals testing randomness of random";
		s += " sources, PRNGs, encryption algorithms.";
		s += "\n\nComments or Suggestions:  aougav@hotmail.com";
		s += "\n\nThis project exploits the power of Java.";
		s += "\n\nJRandTest developed using Eclipse from www.eclipse.org.";

		description.setBackground(Color.cyan);
		description.setText(s);

		setTitle("About JRandTest");
		setResizable(false);
	}

	public synchronized void show()
	{
		Rectangle bounds = getParent().bounds();
		Rectangle abounds = bounds();

		move(
			bounds.x + (bounds.width - abounds.width) / 2,
			bounds.y + (bounds.height - abounds.height) / 2);

		super.show();
	}

	public boolean handleEvent(Event event)
	{
		if (event.id == Event.WINDOW_DESTROY)
		{
			hide();
			return true;
		}
		if (event.target == okButton && event.id == Event.ACTION_EVENT)
		{
			okButton_Clicked(event);
		}
		return super.handleEvent(event);
	}

	void okButton_Clicked(Event event)
	{
		hide();
	}
}
