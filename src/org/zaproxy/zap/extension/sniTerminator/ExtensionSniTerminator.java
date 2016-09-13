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
package org.zaproxy.zap.extension.sniTerminator;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.computerist.zap.ZAPSNITerminator;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;

/*
 * An example ZAP extension which adds a top level menu item. 
 * 
 * This class is defines the extension.
 */
public class ExtensionSniTerminator extends ExtensionAdaptor {

	// Copied from org.zaproxy.zap.extension.dynssl.DynSSLParam
	private static final String PARAM_ROOT_CA = "dynssl.param.rootca";	

	// The name is public so that other extensions can access it
	public static final String NAME = "ExtensionSniTerminator";
	
	// The i18n prefix, by default the package name - defined in one place to make it easier
	// to copy and change this example
	protected static final String PREFIX = "sniTerminator";

    private Logger log = Logger.getLogger(this.getClass());
    
    private ZAPSNITerminator zst = null;
    private SniTermParam params = null;
	private SniTermPanel optionsPanel = null;

	/**
     * 
     */
    public ExtensionSniTerminator() {
        super(NAME);
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

	    if (getView() != null) {
	        extensionHook.getHookView().addOptionPanel(getOptionsPanel());
	    }
        extensionHook.addOptionsParamSet(getParams());
	}
	
	@Override
	public void postInstall() {
		initSniTerminator();
	}

	@Override
	public void unload() {
		super.unload();
		stopTerminator();
	}

	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
    public void postInit() {
		initSniTerminator();
    }

	public void initSniTerminator() {
		// Stop previous instance, if any.
		stopTerminator();

		String serverAddressString = this.getParams().getServerAddress();
		int serverPort = this.getParams().getServerPort();
		
		log.info("Initialize SNI Terminator " + serverAddressString + ":" + serverPort);

		// Read from other configs
		String proxyAddressString = Model.getSingleton().getOptionsParam().getProxyParam().getProxyIp();
		int proxyPort = Model.getSingleton().getOptionsParam().getProxyParam().getProxyPort();
		
		String rootcastr = Model.getSingleton().getOptionsParam().getConfig().getString(PARAM_ROOT_CA, null);
	
		zst = new ZAPSNITerminator(rootcastr, serverAddressString, serverPort, proxyAddressString, proxyPort);
		
		zst.start();
	}
	
	public void startTerminator() {
		if (zst != null) {
			log.debug("startTerminator()");
			zst.start();
		}
	}

	public void stopTerminator() {
		if (zst != null) {
			log.debug("stopTerminator()");
			zst.stop();
		}
	}

	private SniTermPanel getOptionsPanel() {
		if (optionsPanel == null) {
			optionsPanel = new SniTermPanel(this);
		}
		return optionsPanel;
	}

	public SniTermParam getParams() {
		if (params == null) {
			params = new SniTermParam();
		}
		return params;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(PREFIX + ".desc");
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