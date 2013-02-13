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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.history.LogPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import com.crawljax.browser.EmbeddedBrowser.BrowserType;

public class OptionsAjaxSpider extends AbstractParamPanel {


	private static final long serialVersionUID = -1350537974139536669L;

	private ExtensionAjax extension=null;
	private JPanel panelLocalProxy = null;
	private JPanel panelCrawljax = null;
	private JPanel panelProxy = null;
	private ZapTextField txtProxyIp = null;
	private ZapTextField txtNumBro = null;
	private ZapTextField txtNumThre = null;
    
	// ZAP: Do not allow invalid port numbers
	private ZapPortNumberSpinner spinnerProxyPort = null;
	private JCheckBox ClickAllElems = null;
	private JCheckBox firefox = null;
	private JCheckBox chrome = null;
	private JCheckBox ie = null;
	private JCheckBox htmlunit = null;
	private JLabel jLabel6 = null;
	private JLabel browsers = null;
	private JLabel threads = null;
	private static final Logger logger = Logger.getLogger(OptionsAjaxSpider.class);

	/**
	 * Constructor for the class
	 * @param extension
	 */
    public OptionsAjaxSpider(ExtensionAjax extension) {
        super();
    	this.extension=extension;
 		initialize();
   }
    
	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(this.extension.getString("spiderajax.options.title"));
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(391, 320);
	    }
        this.add(getPanelProxy(), getPanelProxy().getName()); 
	}
	
	/**
	 * This method initializes txtNumBro	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapTextField	
	 */    
	private ZapTextField getTxtNumBro() {
		if (txtNumBro == null) {
			txtNumBro = new ZapTextField("");
		}
		return txtNumBro;
	}
	
	/**
	 * This method initializes txtNumThre	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapTextField	
	 */    
	private ZapTextField getTxtNumThre() {
		if (txtNumThre == null) {
			txtNumThre = new ZapTextField("");
		}
		return txtNumThre;
	}
	
	/**
	 * This method initializes txtProxyIp	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapTextField	
	 */    
	private ZapTextField getTxtProxyIp() {
		if (txtProxyIp == null) {
			txtProxyIp = new ZapTextField("");
		}
		return txtProxyIp;
	}
	
	/**
	 * This method initializes spinnerProxyPort	
	 * 	
	 * @return ZapPortNumberSpinner
	 */    
	private ZapPortNumberSpinner getSpinnerProxyPort() {
		if (spinnerProxyPort == null) {
			// ZAP: Do not allow invalid port numbers
			spinnerProxyPort = new ZapPortNumberSpinner(8081);
		}
		return spinnerProxyPort;
	}
	

	/**
	 * 
	 * @return
	 */
	private JCheckBox getClickAllElems() {
			if (ClickAllElems == null) {
				ClickAllElems = new JCheckBox();
				ClickAllElems.setText(this.extension.getString("spiderajax.proxy.local.label.allElems"));
			}
			return ClickAllElems;
		}

	/**
	 * 
	 * @return the firefox checkbox
	 */
	private JCheckBox getFirefox() {
		if (firefox == null) {
			firefox = new JCheckBox();
			firefox.setText(this.extension.getString("spiderajax.proxy.local.label.firefox"));
		}
		return firefox;
	}
	
	/**
	 * 
	 * @return the chrome checkbox
	 */
	private JCheckBox getChrome() {
		if (chrome == null) {
			chrome = new JCheckBox();
			chrome.setText(this.extension.getString("spiderajax.proxy.local.label.chrome"));
		}
		return chrome;
	}
	
	/**
	 * 
	 * @return the IE checkbox
	 */
	private JCheckBox getIE() {
		if (ie == null) {
			ie = new JCheckBox();
			ie.setText(this.extension.getString("spiderajax.proxy.local.label.ie"));
		}
		return ie;
	}
	
	/**
	 * 
	 * @return the IE checkbox
	 */
	private JCheckBox getHtmlunit() {
		if (htmlunit == null) {
			htmlunit = new JCheckBox();
			htmlunit.setText(this.extension.getString("spiderajax.proxy.local.label.htmlunit"));
		}
		return htmlunit;
	}
	
	/**
	 * 
	 */
	@Override
	public void initParam(Object obj) {
	    
	    // set Local Proxy parameters
	    txtProxyIp.setText(this.extension.getProxy().getProxyHost());
	    txtProxyIp.discardAllEdits();
	    spinnerProxyPort.setValue(this.extension.getProxy().getProxyPort());
	    txtNumBro.setText(String.valueOf(this.extension.getProxy().getBrowsers()));
	    txtNumThre.setText(String.valueOf(this.extension.getProxy().getThreads()));
	    
	    //set the browser type
	    if(this.extension.getProxy().getBrowser() == BrowserType.firefox){
	    	this.getFirefox().setSelected(true);
		    this.getChrome().setSelected(false);
		    this.getHtmlunit().setSelected(false);
	    } else if (this.extension.getProxy().getBrowser() == BrowserType.chrome){
		    this.getChrome().setSelected(true);
	    	this.getFirefox().setSelected(false);
		    this.getHtmlunit().setSelected(false);
	    }else if (this.extension.getProxy().getBrowser() == BrowserType.htmlunit){
		    this.getChrome().setSelected(false);
	    	this.getFirefox().setSelected(false);
		    this.getHtmlunit().setSelected(true);
	    }
	}
	
	/**
	 * This method validates the parameters before saving them.
	 */
	@Override
	public void validateParam(Object obj) throws Exception {
		
		//if more than one is selected or none are selected we use firefox
		//if chrome not avail, we use firefox
		//if non selected, we use firefox
		if(getChrome().isSelected() && getHtmlunit().isSelected()){
			getChrome().setSelected(false);
			getHtmlunit().setSelected(false);
			getFirefox().setSelected(true);
			logger.info("Only one browser can be used, switching to the default browser.");
		} else if(getFirefox().isSelected() && getChrome().isSelected()){
			getChrome().setSelected(false);
			getHtmlunit().setSelected(false);
			getFirefox().setSelected(true);
			logger.info("Only one browser can be used, switching to the default browser.");
		} else if(getFirefox().isSelected() && getHtmlunit().isSelected()){
			getChrome().setSelected(false);
			getHtmlunit().setSelected(false);
			getFirefox().setSelected(true);
			logger.info("Only one browser can be used, switching to the default browser.");
		} else if(getHtmlunit().isSelected() && getChrome().isSelected()){
			getChrome().setSelected(false);
			getHtmlunit().setSelected(false);
			getFirefox().setSelected(true);
			logger.info("Only one browser can be used, switching to the default browser.");
		} else if(!getFirefox().isSelected() && !getHtmlunit().isSelected() && !getChrome().isSelected()){
			getChrome().setSelected(false);
			getHtmlunit().setSelected(false);
			getFirefox().setSelected(true);
			logger.info("One browser has to be selected, switching to the default browser.");
		} else if (!getFirefox().isSelected() && getChrome().isSelected()&& !getHtmlunit().isSelected()){
			if(!this.extension.getProxy().isChromeAvail()){
				getChrome().setSelected(false);
				getHtmlunit().setSelected(false);
				getFirefox().setSelected(true);	
				logger.info("ChromeDriver is not available, switching to the default browser.");
				this.extension.showChromeAlert();
			}
		}
	}

	
	/**
	 * this methos sets megascan and the browser type
	 */
	@Override
	public void saveParam(Object obj) throws Exception  {; 
	    this.extension.getProxy().setMegaScan(getClickAllElems().isSelected());
		this.extension.getProxy().setProxyHost(txtProxyIp.getText());
		this.extension.getProxy().setProxyPort(spinnerProxyPort.getValue());
		this.extension.getProxy().setBrowsers(Integer.parseInt(txtNumBro.getText()));
		this.extension.getProxy().setThreads(Integer.parseInt(txtNumThre.getText()));
		
		if(getFirefox().isSelected()){
			this.extension.getProxy().setBrowser(BrowserType.firefox);
		}
		if(getChrome().isSelected()){
			this.extension.getProxy().setBrowser(BrowserType.chrome);
		}
		if(getHtmlunit().isSelected()){
			this.extension.getProxy().setBrowser(BrowserType.htmlunit);
		}
	}


    
	/**
	 * This method initializes panelAjaxProxy
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelLocalProxy() {
		if (panelLocalProxy == null) {
			jLabel6 = new JLabel();
			GridBagConstraints gridBagConstraints15 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints4 = new GridBagConstraints();

			javax.swing.JLabel jLabel = new JLabel();
			javax.swing.JLabel jLabel1 = new JLabel();
			
			panelLocalProxy = new JPanel();
			panelLocalProxy.setLayout(new GridBagLayout());
			panelLocalProxy.setBorder(javax.swing.BorderFactory.createTitledBorder(
					null, this.extension.getString("spiderajax.proxy.local.title"), javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, 
					javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11), java.awt.Color.black));	// ZAP: i18n
			jLabel.setText("Address (eg localhost, 127.0.0.1)");
			gridBagConstraints4.gridx = 0;
			gridBagConstraints4.gridy = 0;
			gridBagConstraints4.ipadx = 0;
			gridBagConstraints4.ipady = 0;
			gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints4.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints4.weightx = 0.5D;
			gridBagConstraints4.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints5.gridx = 1;
			gridBagConstraints5.gridy = 0;
			gridBagConstraints5.weightx = 0.5D;
			gridBagConstraints5.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints5.ipadx = 50;
			gridBagConstraints5.ipady = 0;
			gridBagConstraints5.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints5.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints6.gridx = 0;
			gridBagConstraints6.gridy = 1;
			gridBagConstraints6.ipadx = 0;
			gridBagConstraints6.ipady = 0;
			gridBagConstraints6.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints6.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints6.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints6.weightx = 0.5D;
			gridBagConstraints7.gridx = 1;
			gridBagConstraints7.gridy = 1;
			gridBagConstraints7.weightx = 0.5D;
			gridBagConstraints7.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints7.ipadx = 50;
			gridBagConstraints7.ipady = 0;
			gridBagConstraints7.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints7.insets = new java.awt.Insets(2,2,2,2);
			
	
			
			
			jLabel1.setText(this.extension.getString("spiderajax.proxy.local.label.port"));
			jLabel6.setText(this.extension.getString("spiderajax.proxy.local.label.browser"));
			gridBagConstraints15.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints15.gridx = 0;
			gridBagConstraints15.gridy = 4;
			gridBagConstraints15.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints15.weightx = 1.0D;
			gridBagConstraints15.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints15.gridwidth = 2;
			panelLocalProxy.add(jLabel, gridBagConstraints4);
			panelLocalProxy.add(getTxtProxyIp(), gridBagConstraints5);
			panelLocalProxy.add(jLabel1, gridBagConstraints6);
			panelLocalProxy.add(getSpinnerProxyPort(), gridBagConstraints7);
			panelLocalProxy.add(jLabel6, gridBagConstraints15);
			
		}
		return panelLocalProxy;
	}
	
	
	
	
	
	
	/**
	 * This method initializes panelAjaxProxy
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelCrawljax() {
		if (panelCrawljax == null) {
			jLabel6 = new JLabel();
			java.awt.GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
			
			panelCrawljax = new JPanel();
			panelCrawljax.setLayout(new GridBagLayout());
			panelCrawljax.setBorder(javax.swing.BorderFactory.createTitledBorder(
					null, this.extension.getString("spiderajax.proxy.crawljax.title"), javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, 
					javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11), java.awt.Color.black));	// ZAP: i18n
		
			gridBagConstraints5.gridx = 1;
			gridBagConstraints5.gridy = 0;
			gridBagConstraints5.weightx = 0.5D;
			gridBagConstraints5.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints5.ipadx = 0;
			gridBagConstraints5.ipady = 0;
			gridBagConstraints5.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints5.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints6.gridx = 0;
			gridBagConstraints6.gridy = 1;
			gridBagConstraints6.ipadx = 0;
			gridBagConstraints6.ipady = 0;
			gridBagConstraints6.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints6.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints6.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints6.weightx = 0.5D;
			gridBagConstraints7.gridx = 1;
			gridBagConstraints7.gridy = 1;
			gridBagConstraints7.weightx = 0.5D;
			gridBagConstraints7.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints7.ipadx = 0;
			gridBagConstraints7.ipady = 0;
			gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints7.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints4.gridx = 0;
			gridBagConstraints4.gridy = 0;
			gridBagConstraints4.ipadx = 0;
			gridBagConstraints4.ipady = 0;
			gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints4.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints4.weightx = 0.5D;
			gridBagConstraints4.fill = java.awt.GridBagConstraints.HORIZONTAL;
			
			
			browsers = new JLabel();
			threads = new JLabel();
			
			browsers.setText(this.extension.getString("spiderajax.options.label.browsers"));
			threads.setText(this.extension.getString("spiderajax.options.label.threads"));

			panelCrawljax.add(browsers, gridBagConstraints4);
			panelCrawljax.add(getTxtNumBro(), gridBagConstraints5);
			
			panelCrawljax.add(threads, gridBagConstraints6);
			panelCrawljax.add(getTxtNumThre(), gridBagConstraints7);
		
			javax.swing.JLabel jLabel5 = new JLabel();

			
			panelCrawljax.add(getClickAllElems(), LayoutHelper.getGBC(0, 2, 3,  1.0D, 0, GridBagConstraints.HORIZONTAL, new Insets(2,2,2,2)));
			jLabel5.setText(this.extension.getString("spiderajax.proxy.local.label.browsers"));
			panelCrawljax.add(jLabel5, LayoutHelper.getGBC(0, 3, 3,  1.0D, 0, GridBagConstraints.HORIZONTAL, new Insets(2,2,2,2)));
			panelCrawljax.add(getFirefox(), LayoutHelper.getGBC(0, 4, 3,  1.0D, 1, GridBagConstraints.HORIZONTAL, new Insets(2,2,2,2)));
			panelCrawljax.add(getChrome(), LayoutHelper.getGBC(0, 4, 4,  2.0D, 2, GridBagConstraints.HORIZONTAL+2, new Insets(25,2,2,2)));
			panelCrawljax.add(getHtmlunit(), LayoutHelper.getGBC(0, 4, 4,  2.0D, 2, GridBagConstraints.HORIZONTAL+2, new Insets(50,2,2,2)));
		
		}
		
		return panelCrawljax;
	}
	
	/**
	 * This method initializes panelAjaxProxy	
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelProxy() {
		if (panelProxy == null) {
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
			panelProxy = new JPanel();

			java.awt.GridBagConstraints gridBagConstraints14 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints91 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints81 = new GridBagConstraints();

			javax.swing.JLabel jLabel4 = new JLabel();

			panelProxy.setLayout(new GridBagLayout());

			panelProxy.setName(Constant.messages.getString("options.proxy.local.label.local"));
		    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
		    	panelProxy.setSize(303, 177);
		    }
			panelProxy.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			gridBagConstraints81.gridx = 0;
			gridBagConstraints81.gridy = 0;
			gridBagConstraints81.ipadx = 2;
			gridBagConstraints81.ipady = 4;
			gridBagConstraints81.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints81.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints81.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints81.weightx = 1.0D;
			gridBagConstraints81.weighty = 1.0D;
			gridBagConstraints91.gridx = 0;
			gridBagConstraints91.gridy = 2;
			gridBagConstraints91.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints91.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints91.weightx = 1.0D;
			gridBagConstraints91.weighty = 0.0D;
			gridBagConstraints91.ipady = 4;
			gridBagConstraints91.ipadx = 2;
			jLabel4.setText("");
			gridBagConstraints14.fill = java.awt.GridBagConstraints.BOTH;
			gridBagConstraints14.gridx = 0;
			gridBagConstraints14.gridy = 2;
			gridBagConstraints14.weightx = 1.0D;
			gridBagConstraints14.weighty = 1.0D;
			gridBagConstraints2.gridx = 0;
			gridBagConstraints2.gridy = 1;
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints2.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints2.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints2.weightx = 1.0D;
			panelProxy.add(getPanelLocalProxy(), gridBagConstraints81);
			panelProxy.add(getPanelCrawljax(), gridBagConstraints91);
			panelProxy.add(jLabel4, gridBagConstraints14);
			//TODO add proxy configuration compatibility in crawljax
			//panelProxy.add(getIE(), LayoutHelper.getGBC(0, 4, 4,  2.0D, 2, GridBagConstraints.HORIZONTAL+2, new Insets(50,2,2,2)));

		}
		return panelProxy;
	}

	
	/**
	 * @return the help file of the plugin
	 */
	@Override
	public String getHelpIndex() {
		return "ui.dialogs.options.spiderAjax";
	}
	
  }  //  @jve:decl-index=0:visual-constraint="10,10"