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
 */
package org.zaproxy.zap.extension.advreport;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * An example ZAP extension which adds a top level menu item. 
 * 
 * This class is defines the extension.
 */
public class ExtensionAdvReport extends ExtensionAdaptor {

	public static final String NAME = "ExtensionAdvReport";
	
    private ZapMenuItem menuCustomHtmlReport = null;
    private OptionDialog optionDialog = null;
    private ScopePanel scopetab = null;
    private AlertsPanel alertstab = null;
    private AlertDetailsPanel alertDetailstab = null;
    
    /**
     * 
     */
    public ExtensionAdvReport() {
        super();
        initialize();
    }

    /**
     * @param name
     */
    public ExtensionAdvReport(String name) {
        super(name);
    }

        /**
         * This method initializes this
         * 
         */
        private void initialize() {
        this.setName("ExtensionNewReport");
        }
        
		@Override
		// Hook the extension to the top menu
        public void hook(ExtensionHook extensionHook) {
            super.hook(extensionHook);
            
            if (getView() != null) {
                extensionHook.getHookMenu().addReportMenuItem(getMenuCustomHtmlReport());
            }

        }

        private ZapMenuItem getMenuCustomHtmlReport() {
        if (menuCustomHtmlReport == null) {
                menuCustomHtmlReport = new ZapMenuItem( "menu.report.html.generate" );
                menuCustomHtmlReport.setText("Customize HTML Report");
                menuCustomHtmlReport.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	getNewOptionFrame();
                	optionDialog.setVisible(true);
                	optionDialog.centerFrame();
                }
            });
        }
        return menuCustomHtmlReport;
    }// zap menu item
        
        public void getNewOptionFrame(){
        	//optionframe.setPreferredSize( new Dimension(530,320) );
        	List<String> alertTypes= getAlertTypes();
        	optionDialog = new OptionDialog(getScopeTab(),getAlertsTab( alertTypes ), getAlertDetailsTab() );
        }
        
        private List<String> getAlertTypes() {
        	ExtensionAlert extAlert = (ExtensionAlert) Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.NAME);
            List<Alert> alerts = extAlert.getAllAlerts();
            List<String> alertTypes = new ArrayList<String>();
            for( Alert alert : alerts ){
            	String alertType = alert.getAlert();
            	if( alertTypes.contains( alertType) )continue;
            	alertTypes.add( alertType );
            }
			return alertTypes;
		}
        
        public void generateReport(){
            ReportLastScan report = new ReportLastScan();
            
		    report.generateReport(this.getView(), this.getModel(), this  );
		    this.optionDialog.setVisible( false );
        }

		private ScopePanel getScopeTab(){
        	scopetab = new ScopePanel( this );	
        	return scopetab;
        }
        
        private AlertsPanel getAlertsTab( List<String> alertTypes ){
        	alertstab = new AlertsPanel( alertTypes, this );
        	return alertstab;
        }
        
        private AlertDetailsPanel getAlertDetailsTab(){
        	alertDetailstab = new AlertDetailsPanel( this );
        	return alertDetailstab;
        }
        
        public String getReportName(){
        	return scopetab.getReportName();
        }
        
        public String getReportDescription(){
        	return scopetab.getReportDescription();
        }
        
        public List<String> getSelectedAlerts(){
        	return alertstab.getSelectedAlerts();
        }
        
        public boolean onlyInScope(){
        	return scopetab.onlyInScope();
        }
                
        public String getTemplate(){
        	return scopetab.getTemplate();
        }

        public boolean alertDescription(){
        	return alertDetailstab.description();
        }

        public boolean otherInfo(){
        	return alertDetailstab.otherInfo();
        }
        
        public boolean solution(){
        	return alertDetailstab.solution();
        }
        
        public boolean reference(){
        	return alertDetailstab.reference();
        }
        
        public boolean cweid(){
        	return alertDetailstab.cweid();
        }
        
        public boolean wascid(){
        	return alertDetailstab.wascid();
        }
        
        public boolean requestHeader(){
        	return alertDetailstab.requestHeader();
        }
        
        public boolean responseHeader(){
        	return alertDetailstab.responseHeader();
        }
        
        public boolean requestBody(){
        	return alertDetailstab.requestBody();
        }

        public boolean responseBody(){
        	return alertDetailstab.responseBody();
        }

        @Override
        public String getAuthor() {
                return "\n Author: Chienli Ma";
        }
 
        @Override
        public URL getURL() {
                try {
                        return new URL(Constant.ZAP_EXTENSIONS_PAGE);
                } catch (MalformedURLException e) {
                        return null;
                }
        }

		public void emitFrame() {
			optionDialog.setVisible(false);
		}
}
