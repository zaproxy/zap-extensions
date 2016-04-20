package org.zaproxy.zap.extension.exportReport;

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

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SpringLayout;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.exportReport.Utility.DualListBox;
import org.zaproxy.zap.extension.exportReport.Utility.SharedFunctions;
import org.zaproxy.zap.extension.exportReport.Utility.SpringUtilities;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	PanelAlertRisk.java 
 * DESC			:	Sets up a card with dual lists for inclusion/exclusion of alert risk/severity.
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

public class PanelAlertRisk extends JPanel
{
	private DualListBox				dual		= null;
	private ExtensionExportReport	extension	= null;
	ArrayList<String>				list		= null;
	String[]						arr;

	public PanelAlertRisk(ExtensionExportReport extension, ArrayList<String> list)
	{
		this.extension = extension;
		this.list = list;
		this.arr = new String[this.list.toArray().length];
		initialize();
	}

	private void initialize()
	{
		String strLabel = Constant.messages.getString("exportReport.menu.risk");
		JLabel lblLabel = null;

		JPanel top = null;
		JPanel container = null;
		JPanel content = null;
		SpringLayout sl = null;

		top = new JPanel(new FlowLayout(FlowLayout.LEFT));
		container = new JPanel();
		content = new JPanel();

		this.setLayout(new BorderLayout());
		this.add(top, BorderLayout.PAGE_START);
		lblLabel = SharedFunctions.createLabel(top, lblLabel, strLabel, SharedFunctions.getTitleFont());

		int[] pad =
		{
				0, 0, 295, 360
		};
		content.setLayout(new SpringLayout());
		sl = new SpringLayout();
		container.setLayout(sl);
		this.add(container, BorderLayout.CENTER);
		sl = SharedFunctions.setupConstraints(sl, content, container, pad);
		container.add(content);

		dual = new DualListBox();
		arr = SharedFunctions.appendToArray(list, 0, extension.extensionGetMaxList());
		dual.addSourceElements(arr);
		content.add(dual);
		SpringUtilities.makeCompactGrid(content, 1, 1, 6, 6, 6, 6);
	}

	public ArrayList<String> getSourceListModel()
	{
		return dual.getSourceListModel();
	}
}
