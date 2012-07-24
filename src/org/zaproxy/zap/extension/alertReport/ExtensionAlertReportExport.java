/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2011 The ZAP Development team
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
package org.zaproxy.zap.extension.alertReport;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Vector;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;



/**
 * Extension to Export Alert Selected in PDF to send to customer
 * 
 * 
 * @author leandroferrari
 *
 */
public class ExtensionAlertReportExport extends ExtensionAdaptor implements SessionChangedListener  {

	
	public static final String NAME = "ExtensionAlertReportExports";
	private AlertReportExportMenuItem reportExportMsgPopupMenu = null;
	private OptionsAlertReportExportPanel optionsAlertExportPanel = null;
	private AlertReportExportParam params;
	private ResourceBundle messages = null;
	private Logger logger = Logger.getLogger(ExtensionAlertReportExport.class);


	public AlertReportExportParam getParams() {
		if (params==null)
			params = new AlertReportExportParam();
		return params;
	}

	public void setParams(AlertReportExportParam params) {
		this.params = params;
	}

	private OptionsAlertReportExportPanel getOptionsAlertExportPanel() {
		if (optionsAlertExportPanel == null) {
			optionsAlertExportPanel = new OptionsAlertReportExportPanel();
		}
		return optionsAlertExportPanel;
	}
	
	/**
    * 
    */
	public ExtensionAlertReportExport() {
		super();
		initialize();
	}


	/**
	 * @param name
	 */
	public ExtensionAlertReportExport(String name) {
		super(name);
	}
	
	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		this.setName("ExtensionReportExport");
		 // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
	}
	

	@Override
	public void initView(ViewDelegate view) {
		super.initView(view);
	}


	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		if (getView() != null) {
			extensionHook.getHookMenu().addPopupMenuItem(getAlertExportMsgPopupMenu());
			extensionHook.getHookView().addOptionPanel(getOptionsAlertExportPanel());
			extensionHook.addOptionsParamSet(getParams());
		}

	}

	private AlertReportExportMenuItem getAlertExportMsgPopupMenu() {
		if (reportExportMsgPopupMenu == null) {
			reportExportMsgPopupMenu = new AlertReportExportMenuItem(
					this.getMessageString("alert.export.message.menuitem"));
			reportExportMsgPopupMenu.setExtension(this);
		}
		return reportExportMsgPopupMenu;
	}

	public String getMessageString(String key) {
		return messages.getString(key);
	}

	@Override
	public String getAuthor() {
		return "Talsoft SRL";
	}

	@Override
	public String getDescription() {
		return this.getMessageString("alert.export.message.desc");
	}
	
    
   
	@Override
	public URL getURL() {
		try {
			return new URL("http://www.talsoft.com.ar");
		} catch (MalformedURLException e) {
			return null;
		}
	}


	/**
	 * get Alerts from DB
	 * @return
	 */
	public List getAllAlerts() {
        List allAlerts = new ArrayList();

        TableAlert tableAlert = getModel().getDb().getTableAlert();
        Vector v;
        try {
            v = tableAlert.getAlertList();

            for (int i = 0; i < v.size(); i++) {
                int alertId = ((Integer) v.get(i)).intValue();
                RecordAlert recAlert = tableAlert.read(alertId);
                Alert alert = new Alert(recAlert);
                if (!allAlerts.contains(alert)) {
                    allAlerts.add(alert);
                }
            }
        } catch (SQLException e) {
            logger.error(e.getMessage(), e);
        }
        return allAlerts;
    }
	

	
	/**
	 * Get fileName of alert pdf
	 * @param alert
	 * @return
	 */
	public String getFileName() {
	    
	    JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
	    // set filename alert
	    File fileproposal = new File("CodeOWASP_Alert_Report"+".pdf");
	    chooser.setSelectedFile(fileproposal);
	    chooser.setFileFilter(new FileFilter() {
	           @Override
	           public boolean accept(File file) {
	                if (file.isDirectory()) {
	                    return true;
	                } else if (file.isFile() && file.getName().endsWith(".pdf")) {
	                    return true;
	                }
	                return false;
	            }
	           @Override
	           public String getDescription() {
	        	   // ZAP: Rebrand
	               return "PDF File";
	           }
	    });
		File file = null;
		String fileName = "";
	    int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
	    if(rc == JFileChooser.APPROVE_OPTION) {
    		file = chooser.getSelectedFile();
    		if (file == null) {
    			return "";
    		}
           fileName = file.getAbsolutePath();
    		if (!fileName.endsWith(".pdf")) {
    		    fileName += ".pdf";
    		}
    		
	    }
		return fileName;
	}

	 /**
	 * get alerts from same Plugin ID
	 * @param alertSelected
	 * @return
	 */
	public List getAlertsSelected(Alert alertSelected){
		List alertsAll = this.getAllAlerts();
		List alerts = new ArrayList();
		for (int i = 0; i < alertsAll.size(); i++) {
			Alert alert = (Alert) alertsAll.get(i);
			if (alertSelected.getAlert().equals(alert.getAlert()))
				alerts.add(alert);
		}
		
		return alerts; 
	}
	
	@Override
	public void sessionChanged(Session session) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void sessionAboutToChange(Session session) {
		// TODO Auto-generated method stub
		
	}



}
