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
package org.zaproxy.zap.extension.gettingStarted;

import java.awt.Desktop;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * An example ZAP extension which adds a top level menu item. 
 * 
 * This class is defines the extension.
 */
public class ExtensionGettingStarted extends ExtensionAdaptor {

	private static final String DIR = "lang";
    private ZapMenuItem menuGettingStarted = null;
    private Logger logger = Logger.getLogger(getClass());

	/**
     * 
     */
    public ExtensionGettingStarted() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionGettingStarted(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setName("ExtensionGettingStarted");
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    if (getView() != null) {
	    	// Register our top menu item, as long as we're not running as a daemon
	    	// Use one of the other methods to add to a different menu list
	        extensionHook.getHookMenu().addHelpMenuItem(getMenuGettingStarted());
	    }

	}

	private ZapMenuItem getMenuGettingStarted() {
        if (menuGettingStarted == null) {
        	menuGettingStarted = new ZapMenuItem("gettingStarted.menu");
        	menuGettingStarted.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	try {
                		/*
                		 * Note that if you translate the guide to another language you need to also change
                		 * the language file so that gettingStarted.file refers to the localized file name
                		 */
                		File guide = new File(Constant.getZapHome() + File.separator + DIR + File.separator + 
                				Constant.messages.getString("gettingStarted.file"));
                		logger.debug("Getting started guide: " + guide.getAbsolutePath());
						Desktop.getDesktop().open(guide);
					} catch (Exception e1) {
						logger.error(e1.getMessage(), e1);
					}
                }
            });
        }
        return menuGettingStarted;
    }

	@Override
	public boolean canUnload() {
		return true;
	}
	
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("gettingStarted.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_EXTENSIONS_PAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
}