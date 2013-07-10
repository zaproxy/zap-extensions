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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.help.ExtensionHelp;

/**
 * Main class of the plugin, it instantiates the rest of them.
 *  @author Guifre Ruiz Utges
 */
public class ExtensionAjax extends ExtensionAdaptor {

	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);
	public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
	public static final String NAME = "ExtensionSpiderAjax";

	private SpiderPanel spiderPanel = null;
	private PopupMenuAjax popupMenuSpider = null;
	private PopupMenuAjaxSite popupMenuSpiderSite = null;
	private PopupMenuAjaxSiteInScope popupMenuInScope = null;
	private OptionsAjaxSpider optionsAjaxSpider = null;
	private List<String> excludeList = null;
	private ProxyAjax proxy = null;
	private ChromeAlertDialog addDialog = null;
	//private ScopeController scope = null;
	private String mode = null;

	/**
	 * initializes the extension
	 * @throws ClassNotFoundException 
	 */
	public ExtensionAjax() throws ClassNotFoundException {
		super(NAME);
		initialize();
	}

	/**
	 * @return the new ajax proxy
	 */
	public ProxyAjax getProxy() {
		if (this.proxy == null) {
			this.proxy = new ProxyAjax(this);
		}
		return this.proxy;
	}


	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
		this.setName(NAME);
		this.setI18nPrefix("spiderajax");
		this.setOrder(234);
		//TODO: fix the mode & scope things
		//this.scope = new ScopeController();
		//this.mode = this.getModel().getOptionsParam().getViewParam().getMode();
	}

	/**
	 * starts the proxy and all elements of the UI
	 * @param extensionHook the extension
	 */
	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		if (getView() != null) {
			@SuppressWarnings("unused")
			ExtensionHookView pv = extensionHook.getHookView();
			extensionHook.getHookView().addStatusPanel(getSpiderPanel());
			this.getSpiderPanel().setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
			extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());
			//scope control
			//extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpider());
			//extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAjaxSiteInScope());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAjaxSite());
			ExtensionHelp.enableHelpKey(getSpiderPanel(), "ui.tabs.spiderAjax");
		}
	}
	
    @Override
	public boolean canUnload() {
    	return true;
    }
	
    @Override
    public void unload() {
        if (getView() != null) {
            getSpiderPanel().stopScan();
            
            if (addDialog != null) {
                addDialog.dispose();
            }
            
            if (proxy != null) {
                proxy.stopServer();
            }
            
            getView().getMainFrame().getMainFooterPanel().removeFooterToolbarRightLabel(getSpiderPanel().getScanStatus().getCountLabel());
        }
        
        super.unload();
    }

	/*public void getMode() {
		if(this.getModel().getOptionsParam().getViewParam().getMode().equals("safe")) {
		} else if(this.getModel().getOptionsParam().getViewParam().getMode().equals("protect")) {
					
		} else if(this.getModel().getOptionsParam().getViewParam().getMode().equals("standard}")) {
					
		}
	}*/
	/**
	 * Creates the panel with the config of the proxy
	 * @return the panel
	 */
	protected SpiderPanel getSpiderPanel() {
		if (spiderPanel == null) {
			spiderPanel = new SpiderPanel(this);
			spiderPanel.setName(this.getMessages().getString("spiderajax.panel.title"));
			spiderPanel.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/spiderAjax.png")));
			}
		return spiderPanel;
	}

	/**
	 * 
	 * @return the PopupMenuAjax object
	 */
	private PopupMenuAjax getPopupMenuSpider() {
		if (popupMenuSpider == null) {
			popupMenuSpider = new PopupMenuAjax(this);
			popupMenuSpider.setExtension(this);
		}
		return popupMenuSpider;
	}
	
	
	/**
	 * 
	 * @return the PopupMenuSpiderSiteInScope object
	 */
	private PopupMenuAjaxSiteInScope getPopupMenuAjaxSiteInScope() {
		if (popupMenuInScope == null) {
			popupMenuInScope = new PopupMenuAjaxSiteInScope(this.getMessages().getString("spiderajax.site.popup.InScope"), this);
		}
		return popupMenuInScope;
	}

	/**
	 * 
	 * @return the PopupMenuAjaxSite object
	 */
	private PopupMenuAjaxSite getPopupMenuAjaxSite() {
		if (popupMenuSpiderSite == null) {
			popupMenuSpiderSite = new PopupMenuAjaxSite(this.getMessages().getString("spiderajax.site.popup"), this);
		}
		return popupMenuSpiderSite;
	}

	/**
	 * 
	 * @return
	 */
	private OptionsAjaxSpider getOptionsSpiderPanel() {
		if (optionsAjaxSpider == null) {
			optionsAjaxSpider = new OptionsAjaxSpider(this);
		}
		return optionsAjaxSpider;
	}

	/**
	 *  calls the spider
	 * @param node
	 * @param incPort
	 */
	public void spiderSite(SiteNode node, boolean inScope) {
		this.getSpiderPanel().scanSite(node, inScope);
	}


	/**
	 * 
	 * @param ignoredRegexs
	 */
	public void setExcludeList(List<String> ignoredRegexs) {
		this.excludeList = ignoredRegexs;
	}

	/**
	 * 
	 * @return the exclude list
	 */
	public List<String> getExcludeList() {
		return excludeList;
	}

	/**
	 * 	 
	 * @return the author
	 */
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}
	
	/**
	 * 
	 * @return description of the plugin
	 */
	@Override
	public String getDescription() {
		return this.getMessages().getString("spiderajax.desc");
	}
	
	/**
	 * 
	 * @return the url of the proj
	 */
	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			logger.error(e);
			return null;
		}
	}
	
	/**
	 * @param url the targeted url
	 */
	public void run(String url, boolean inScope) {
		this.spiderPanel.newScanThread(url, this.getProxy().getAjaxProxyParam(), inScope);
	}

	/**
	 * shows the chrome alert
	 */
	public void showChromeAlert() {
		addDialog = new ChromeAlertDialog(getView().getMainFrame(), false, this);
		addDialog.setVisible(true);
	}
	
}