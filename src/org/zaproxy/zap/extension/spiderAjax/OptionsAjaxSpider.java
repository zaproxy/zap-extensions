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

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam.Browser;
import org.zaproxy.zap.utils.ZapNumberSpinner;

public class OptionsAjaxSpider extends AbstractParamPanel {

	private static final String WEBDRIVER_CHROME_DRIVER_SYSTEM_PROPERTY = "webdriver.chrome.driver";

	private static final long serialVersionUID = -1350537974139536669L;

	private ExtensionAjax extension=null;
	private JPanel panelCrawljax = null;
	private ZapNumberSpinner txtNumBro = null;
    
	private JCheckBox ClickAllElems = null;
	private JRadioButton firefox = null;
	private JRadioButton chrome = null;
	private JRadioButton ie = null;
	private JRadioButton htmlunit = null;
	private JButton selectChromeDriverButton;
	private JLabel browsers = null;
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
        this.setLayout(new BorderLayout());
        this.setName(this.extension.getMessages().getString("spiderajax.options.title"));
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(391, 320);
	    }
        this.add(getPanelCrawljax(), BorderLayout.PAGE_START); 
	}
	
	/**
	 * This method initializes txtNumBro	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapNumberSpinner	
	 */    
	private ZapNumberSpinner getTxtNumBro() {
		if (txtNumBro == null) {
			txtNumBro = new ZapNumberSpinner(1, 1, Integer.MAX_VALUE);
		}
		return txtNumBro;
	}
	

	/**
	 * 
	 * @return
	 */
	private JCheckBox getClickAllElems() {
			if (ClickAllElems == null) {
				ClickAllElems = new JCheckBox();
				ClickAllElems.setText(this.extension.getMessages().getString("spiderajax.proxy.local.label.allElems"));
			}
			return ClickAllElems;
		}

	/**
	 * 
	 * @return the firefox radio button
	 */
	private JRadioButton getFirefox() {
		if (firefox == null) {
			firefox = new JRadioButton();
			firefox.setText(this.extension.getMessages().getString("spiderajax.proxy.local.label.firefox"));
		}
		return firefox;
	}
	
	/**
	 * 
	 * @return the chrome radio button
	 */
	private JRadioButton getChrome() {
		if (chrome == null) {
			chrome = new JRadioButton();
			chrome.setText(this.extension.getMessages().getString("spiderajax.proxy.local.label.chrome"));
		}
		return chrome;
	}
	
	/**
	 * 
	 * @return the IE radio button
	 */
	private JRadioButton getIE() {
		if (ie == null) {
			ie = new JRadioButton();
			ie.setText(this.extension.getMessages().getString("spiderajax.proxy.local.label.ie"));
		}
		return ie;
	}
	
	/**
	 * 
	 * @return the Htmlunit radio button
	 */
	private JRadioButton getHtmlunit() {
		if (htmlunit == null) {
			htmlunit = new JRadioButton();
			htmlunit.setText(this.extension.getMessages().getString("spiderajax.proxy.local.label.htmlunit"));
		}
		return htmlunit;
	}
	
	/**
	 * 
	 */
	@Override
	public void initParam(Object obj) {
	    
	    OptionsParam optionsParam = (OptionsParam) obj;
	    AjaxSpiderParam ajaxSpiderParam = (AjaxSpiderParam) optionsParam.getParamSet(AjaxSpiderParam.class);

	    txtNumBro.setValue(Integer.valueOf(ajaxSpiderParam.getNumberOfBrowsers()));
	    getClickAllElems().setSelected(ajaxSpiderParam.isCrawlInDepth());
	    
	    switch (ajaxSpiderParam.getBrowser()) {
	    case FIREFOX:
	    	this.getFirefox().setSelected(true);
	    	break;
	    case CHROME:
	    	this.getChrome().setSelected(true);
	    	break;
	    case HTML_UNIT:
	    	this.getHtmlunit().setSelected(true);
	    	break;
	    default:
	    	this.getFirefox().setSelected(true);
	    }
	}
	
	/**
	 * This method validates the parameters before saving them.
	 */
	@Override
	public void validateParam(Object obj) throws Exception {
		
		if(getChrome().isSelected() && !this.extension.isChromeAvail()){
			getFirefox().setSelected(true);	
			logger.info("ChromeDriver is not available, switching to the default browser.");
			this.extension.showChromeAlert();
		}
	}

	@Override
	public void saveParam(Object obj) throws Exception  {; 
		OptionsParam optionsParam = (OptionsParam) obj;
		AjaxSpiderParam ajaxSpiderParam = (AjaxSpiderParam) optionsParam.getParamSet(AjaxSpiderParam.class);

		ajaxSpiderParam.setCrawlInDepth(getClickAllElems().isSelected());
		ajaxSpiderParam.setNumberOfBrowsers(txtNumBro.getValue().intValue());
		
		if(getFirefox().isSelected()){
			ajaxSpiderParam.setBrowser(Browser.FIREFOX);
		} else if(getChrome().isSelected()){
			ajaxSpiderParam.setBrowser(Browser.CHROME);
		} else if(getHtmlunit().isSelected()){
			ajaxSpiderParam.setBrowser(Browser.HTML_UNIT);
		}
	}

	private JButton getSelectChromeDriverButton() {
		if (selectChromeDriverButton == null) {
			selectChromeDriverButton = new JButton(this.extension.getMessages().getString(
					"spiderajax.options.select.chrome.driver.button.label"));
			selectChromeDriverButton.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					JFileChooser fileChooser = new JFileChooser();
					String path = System.getProperty(WEBDRIVER_CHROME_DRIVER_SYSTEM_PROPERTY);
					if (path != null) {
						File file = new File(path);
						if (file.exists()) {
							fileChooser.setSelectedFile(file);
						}
					}
					if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
						final File selectedFile = fileChooser.getSelectedFile();

						System.setProperty(WEBDRIVER_CHROME_DRIVER_SYSTEM_PROPERTY, selectedFile.getAbsolutePath());
					}
				}
			});
		}
		return selectChromeDriverButton;
	}

	/**
	 * This method initializes panelAjaxProxy
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelCrawljax() {
		if (panelCrawljax == null) {
			panelCrawljax = new JPanel(new GridBagLayout());
			
			ButtonGroup browsersButtonGroup = new ButtonGroup();
			browsersButtonGroup.add(getFirefox());
			browsersButtonGroup.add(getChrome());
			browsersButtonGroup.add(getHtmlunit());
			
			browsers = new JLabel(this.extension.getMessages().getString("spiderajax.options.label.browsers"));

			GridBagConstraints gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.fill = GridBagConstraints.HORIZONTAL;
			gbc.insets = new java.awt.Insets(2,2,2,2);
			gbc.anchor = GridBagConstraints.LINE_START;
			gbc.weightx = 0.5D;

			panelCrawljax.add(browsers, gbc);
			gbc.gridx++;
			gbc.anchor = GridBagConstraints.LINE_END;
			
			panelCrawljax.add(getTxtNumBro(), gbc);
			gbc.gridx = 0;
			gbc.gridwidth = 2;
			gbc.anchor = GridBagConstraints.LINE_START;
			gbc.weightx = 1.0D;

			panelCrawljax.add(getClickAllElems(), gbc);

			panelCrawljax.add(new JLabel(this.extension.getMessages().getString("spiderajax.proxy.local.label.browsers")), gbc);
			gbc.gridwidth = 1;

			panelCrawljax.add(getFirefox(), gbc);

			panelCrawljax.add(getChrome(), gbc);

			panelCrawljax.add(getHtmlunit(), gbc);

			gbc.fill = GridBagConstraints.NONE;
			gbc.insets = new java.awt.Insets(8,2,2,2);
			panelCrawljax.add(getSelectChromeDriverButton(), gbc);
		}
		
		return panelCrawljax;
	}
	
	/**
	 * @return the help file of the plugin
	 */
	@Override
	public String getHelpIndex() {
		return "ui.dialogs.options.spiderAjax";
	}
	
  }  //  @jve:decl-index=0:visual-constraint="10,10"