/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 ZAP development team
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

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.BrowserUI;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AjaxSpiderDialog extends StandardFieldsDialog {
	
	protected static final String[] LABELS = {
		"spiderajax.scandialog.tab.scope",
		"spiderajax.scandialog.tab.options",
		/*"spiderajax.scandialog.tab.elements"*/};

    private static final String FIELD_START = "spiderajax.scandialog.label.start";
    private static final String FIELD_IN_SCOPE = "spiderajax.scandialog.label.inscope";
    private static final String FIELD_BROWSER = "spiderajax.scandialog.label.browser";
    private static final String FIELD_ADVANCED = "spiderajax.scandialog.label.adv";
    
    private static final String FIELD_NUM_BROWSERS = "spiderajax.options.label.browsers";
    
    private static final String FIELD_DEPTH = "spiderajax.options.label.depth";
    private static final String FIELD_CRAWL_STATES = "spiderajax.options.label.crawlstates";
    private static final String FIELD_DURATION  = "spiderajax.options.label.maxduration";
    private static final String FIELD_EVENT_WAIT = "spiderajax.options.label.eventwait";
    private static final String FIELD_RELOAD_WAIT = "spiderajax.options.label.reloadwait";


    private static final Logger logger = Logger.getLogger(AjaxSpiderDialog.class);
    private static final long serialVersionUID = 1L;

    private ExtensionAjax extension = null;
    private ExtensionSelenium extSel = null;

    private SiteNode startNode = null;
	private AjaxSpiderParam params = null;
	//private OptionsAjaxSpiderTableModel ajaxSpiderClickModel = null;

    public AjaxSpiderDialog(ExtensionAjax ext, Frame owner, Dimension dim) {
        super(owner, "spiderajax.scandialog.title", dim, LABELS);
        
        this.extension = ext;
    }

    public void init(SiteNode startNode) {
        if (startNode != null) {
            // If one isnt specified then leave the previously selected one
            this.startNode = startNode;
        }
        
        logger.debug("init " + this.startNode);
        if (params == null) {
        	params = this.extension.getAjaxSpiderParam();
        }

        this.removeAllFields();

        this.addNodeSelectField(0, FIELD_START, this.startNode, false, false);
        this.addCheckBoxField(0, FIELD_IN_SCOPE, false);
        
        if (getExtSelenium() != null) {
        	List<Browser> browserList = getExtSelenium().getConfiguredBrowsers();
        	List <String> browserNames = new ArrayList<String>(); 
        	String defaultBrowser = null;
        	for (Browser browser : browserList) {
        		browserNames.add(extSel.getName(browser));
        		if (browser.getId().equals(params.getBrowserId())) {
        			defaultBrowser = extSel.getName(browser);
        		}
        	}
        	
    		this.addComboField(0, FIELD_BROWSER, browserNames, defaultBrowser);
        }

        // This option is always read from the 'global' options
        this.addCheckBoxField(0, FIELD_ADVANCED, params.isShowAdvancedDialog());

        this.addPadding(0);

        this.addFieldListener(FIELD_ADVANCED, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Save the adv option permanently for next time

                setAdvancedOptions(getBoolValue(FIELD_ADVANCED));
            }
        });

        if (startNode != null) {
            // Set up the fields if a node has been specified, otherwise leave as previously set
	        this.siteNodeSelected(FIELD_START, this.startNode);
        }

        this.setAdvancedOptions(params.isShowAdvancedDialog());
        
        // Options tab
        this.addNumberField(1, FIELD_NUM_BROWSERS, 1, Integer.MAX_VALUE, params.getNumberOfBrowsers());
        this.addNumberField(1, FIELD_DEPTH, 0, Integer.MAX_VALUE, params.getMaxCrawlDepth());
        this.addNumberField(1, FIELD_CRAWL_STATES, 0, Integer.MAX_VALUE, params.getMaxCrawlStates());
        this.addNumberField(1, FIELD_DURATION, 0, Integer.MAX_VALUE, params.getMaxDuration());
        this.addNumberField(1, FIELD_EVENT_WAIT, 1, Integer.MAX_VALUE, params.getEventWait());
        this.addNumberField(1, FIELD_RELOAD_WAIT, 1, Integer.MAX_VALUE, params.getReloadWait());
        
        this.addPadding(1);
        
        /* Need to check this really works before releasing it
        getAjaxSpiderClickModel().setElems(params.getElems());
        this.setCustomTabPanel(2, new AjaxSpiderMultipleOptionsPanel(getAjaxSpiderClickModel()));
        */

        this.pack();
    }
    
    private ExtensionSelenium getExtSelenium() {
    	if (extSel == null) {
    		extSel = (ExtensionSelenium) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.NAME);
    	}
    	return extSel;
    }

    /*
	private OptionsAjaxSpiderTableModel getAjaxSpiderClickModel() {
		if (ajaxSpiderClickModel == null) {
			ajaxSpiderClickModel = new OptionsAjaxSpiderTableModel();
		}
		return ajaxSpiderClickModel;
	}
	*/

    @Override
    public String getHelpIndex() {
    	return "addon.spiderajax.dialog";
    }

    
    private void setAdvancedOptions(boolean adv) {
        this.setTabsVisible(new String[]{
        		"spiderajax.scandialog.tab.options",
        		/*"spiderajax.scandialog.tab.elements"*/
            }, adv);
        // Always save in the 'global' options
        extension.getAjaxSpiderParam().setShowAdvancedDialog(adv);
    }

    @Override
    public void siteNodeSelected(String field, SiteNode node) {
        if (node != null) {
            // The user has selected a new node
            this.startNode = node;
        }
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("spiderajax.scandialog.button.scan");
    }

    /**
     * Use the save method to launch a scan
     */
    @Override
    public void save() {
    	AjaxSpiderParam params = this.extension.getAjaxSpiderParam().clone();
    	
        Browser selectedBrowser = getSelectedBrowser();
        if (selectedBrowser != null) {
            params.setBrowserId(selectedBrowser.getId());
        }

        if (this.getBoolValue(FIELD_ADVANCED)) {
        	params.setNumberOfBrowsers(this.getIntValue(FIELD_NUM_BROWSERS));
        	params.setMaxCrawlDepth(this.getIntValue(FIELD_DEPTH));
        	params.setMaxCrawlStates(this.getIntValue(FIELD_CRAWL_STATES));
        	params.setMaxDuration(this.getIntValue(FIELD_DURATION));
        	params.setEventWait(this.getIntValue(FIELD_EVENT_WAIT));
        	params.setReloadWait(this.getIntValue(FIELD_RELOAD_WAIT));
        	
            //params.setElems(getAjaxSpiderClickModel().getElements());
        	
        }

    	this.extension.spiderSite(this.startNode, this.getBoolValue(FIELD_IN_SCOPE), params);
    }

    /**
     * Gets the selected browser.
     *
     * @return the selected browser, {@code null} if none selected
     */
    private Browser getSelectedBrowser() {
        if (isEmptyField(FIELD_BROWSER)) {
            return null;
        }

        String browserName = this.getStringValue(FIELD_BROWSER);
        List<BrowserUI> browserList = getExtSelenium().getBrowserUIList();
        for (BrowserUI bui : browserList) {
            if (browserName.equals(bui.getName())) {
                return bui.getBrowser();
            }
        }
        return null;
    }

    @Override
    public String validateFields() {

        if (this.startNode == null) {
            return Constant.messages.getString("spiderajax.scandialog.nostart.error");
        }

        Browser selectedBrowser = getSelectedBrowser();
        if (selectedBrowser == null) {
            return null;
        }

        if (Browser.PHANTOM_JS.getId() == selectedBrowser.getId()) {
            try {
                String host = startNode.getHistoryReference().getURI().getHost();
                if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host)) {
                    return Constant.messages.getString("spiderajax.warn.message.phantomjs.bug.invalid.target");
                }
            } catch (URIException e) {
                logger.warn("Failed to get host:", e);
            }
        }

        return null;
    }

}
