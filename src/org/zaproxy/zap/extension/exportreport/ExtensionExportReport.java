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
package org.zaproxy.zap.extension.exportreport;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

import org.zaproxy.zap.extension.exportreport.Export.ExportReport;
import org.zaproxy.zap.extension.exportreport.Utility.SharedFunctions;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 */

public class ExtensionExportReport extends ExtensionAdaptor
{

	private static final String			NAME				= "ExtensionExportReport";
	private static final String			FONT				= "Arial";
	
	private ZapMenuItem					menuExportReport	= null;
	private FrameExportReport			frameER				= null;

	protected final Map<String, String>	alertTypeRisk		= new HashMap<>();

	/* Nav Panel creation. */
	private PanelSource					cardSource			= null;
	private PanelAlertRisk				cardAlertRisk		= null;
	private PanelAlertDetails			cardAlertDetails	= null;

	/* Field Limit Constants */
	private final int					textfieldLimit		= 30;
	private final int					textareaLimit		= 600;

	/* Relational CONSTANT for export types. */
	private ArrayList<String>			alertSeverity		= new ArrayList<String>();
	private ArrayList<String>			alertDetails		= new ArrayList<String>();
	private ArrayList<String>			alertAdditional		= new ArrayList<String>();
	private int							maxList				= 0;
	
	public ExtensionExportReport()
	{
		super();
		initialize();
	}

	public ExtensionExportReport(String name)
	{
		super(name);
	}

	private void initialize()
	{
		this.setName(NAME);
		SharedFunctions.fontExists(FONT);		
	}

	@Override
	public void hook(ExtensionHook extensionHook)
	{
		super.hook(extensionHook);
		if (getView() != null)
		{
			extensionHook.getHookMenu().addReportMenuItem(getMenuExportReport());
		}
	}

	@Override
	public boolean canUnload()
	{
		return true;
	}

	@Override
	public void unload()
	{
		super.unload();
		if (frameER != null)
		{
			frameER.dispose();
			frameER = null;
		}
	}

	private ZapMenuItem getMenuExportReport()
	{
		if (menuExportReport == null)
		{
			menuExportReport = new ZapMenuItem("exportreport.menu.export.label");
			//menuExportReport.setText(Constant.messages.getString("exportreport.menu.export.label"));
			menuExportReport.addActionListener(new java.awt.event.ActionListener()
			{
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e)
				{
					if (frameER != null)
					{
						frameER.requestFocusInWindow();
						return;
					}
					
					getNewOptionFrame();
					
					// -Change the default close operation
					WindowAdapter exitListener = new WindowAdapter() {
					    @Override
					    public void windowClosing(WindowEvent e) {
					    	emitFrame();
					    }
					};
					frameER.addWindowListener(exitListener);
					frameER.setSize(400, 500);
					frameER.setResizable(false);
					frameER.setVisible(true);
					frameER.centerFrame();//frameER.setLocationRelativeTo(null);
				}
			});
		}
		return menuExportReport;
	}

	public void getNewOptionFrame()
	{
		initializeLists();
		frameER = new FrameExportReport(this, extensionGetCardSource(),extensionGetCardAlertRisk(),extensionGetCardAlertDetails());
	}

	private void initializeLists()
	{
		// PanelAlertRisk
		alertSeverity.clear();
		alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.high.label"));
		alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.medium.label"));
		alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.low.label"));
		alertSeverity.add(Constant.messages.getString("exportreport.risk.severity.info.label"));

		// PanelAlertDetails
		alertDetails.clear();
		alertDetails.add(Constant.messages.getString("exportreport.details.cweid.label"));
		alertDetails.add(Constant.messages.getString("exportreport.details.wascid.label"));
		alertDetails.add(Constant.messages.getString("exportreport.details.description.label"));
		alertDetails.add(Constant.messages.getString("exportreport.details.otherinfo.label"));
		alertDetails.add(Constant.messages.getString("exportreport.details.solution.label"));
		alertDetails.add(Constant.messages.getString("exportreport.details.reference.label"));

		alertAdditional.clear();
		alertAdditional.add(Constant.messages.getString("exportreport.details.requestheader.label"));
		alertAdditional.add(Constant.messages.getString("exportreport.details.responseheader.label"));
		alertAdditional.add(Constant.messages.getString("exportreport.details.requestbody.label"));
		alertAdditional.add(Constant.messages.getString("exportreport.details.responsebody.label"));

		maxList = (alertDetails.size() + alertAdditional.size());
	}
	
	private PanelSource extensionGetCardSource()
	{
		cardSource = new PanelSource(this);
		return cardSource;
	}

	private PanelAlertRisk extensionGetCardAlertRisk()
	{
		cardAlertRisk = new PanelAlertRisk(this, alertSeverity);
		return cardAlertRisk;
	}

	private PanelAlertDetails extensionGetCardAlertDetails()
	{
		cardAlertDetails = new PanelAlertDetails(this, alertDetails, alertAdditional);
		return cardAlertDetails;
	}

	public int extensionGetMaxList()
	{
		return maxList;
	}

	/* Source Card return data */
	public String extensionGetTitle()
	{
		return cardSource.getTitle();
	}

	public String extensionGetBy()
	{
		return cardSource.getBy();
	}

	public String extensionGetFor()
	{
		return cardSource.getFor();
	}

	public String extensionGetScanDate()
	{
		return cardSource.getScanDate();
	}

	public String extensionGetReportDate()
	{
		return cardSource.getReportDate();
	}

	public String extensionGetScanVer()
	{
		return cardSource.getScanVer();
	}

	public String extensionGetReportVer()
	{
		return cardSource.getReportVer();
	}

	public String extensionGetDescription()
	{
		return cardSource.getDescription();
	}

	/* Alert Risk Card return data */
	public ArrayList<String> getIncludedAlertSeverity()
	{
		return cardAlertRisk.getSourceListModel();
	}

	/* Alert Details Card return data */
	public ArrayList<String> getIncludedAlertDetails()
	{
		return cardAlertDetails.getSourceListModel();
	}

	public int getTextfieldLimit()
	{
		return textfieldLimit;
	}

	public int getTextfieldNoLimit()
	{
		return -1;
	}

	public int getTextareaLimit()
	{
		return textareaLimit;
	}

	@Override
	public String getAuthor()
	{
		return "\n Author: Goran Sarenkapa - JordanGS";
	}

	public void emitFrame()
	{
		frameER.setVisible(false);
		frameER.dispose();
		frameER = null;
	}

	public void generateReport()
	{
		ExportReport report = new ExportReport();
		report.generateReport(this.getView(), this);
		this.emitFrame();
	}
}