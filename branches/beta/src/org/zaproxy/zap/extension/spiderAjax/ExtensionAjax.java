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
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
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
	private boolean spiderRunning;
	private SpiderListener spiderListener;
	private AjaxSpiderAPI ajaxSpiderApi;
	private AjaxSpiderParam ajaxSpiderParam;

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
			this.proxy = new ProxyAjax(this, getAjaxSpiderParam(), Model.getSingleton().getOptionsParam().getConnectionParam());
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
	}

	@Override
	public void init() {
		super.init();
		
		ajaxSpiderApi = new AjaxSpiderAPI(this);
	}

	/**
	 * starts the proxy and all elements of the UI
	 * @param extensionHook the extension
	 */
	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		API.getInstance().registerApiImplementor(ajaxSpiderApi);
		extensionHook.addOptionsParamSet(getAjaxSpiderParam());

		if (getView() != null) {
			extensionHook.addSessionListener(new SpiderSessionChangedListener());

			@SuppressWarnings("unused")
			ExtensionHookView pv = extensionHook.getHookView();
			extensionHook.getHookView().addStatusPanel(getSpiderPanel());
			this.getSpiderPanel().setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
			extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());
			//scope control
			//extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpider());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAjaxSiteInScope());
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
            
            getView().getMainFrame().getMainFooterPanel().removeFooterToolbarRightLabel(getSpiderPanel().getScanStatus().getCountLabel());
        }
        
        if (proxy != null) {
            proxy.stopServer();
        }

        super.unload();
    }

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

	AjaxSpiderParam getAjaxSpiderParam() {
		if (ajaxSpiderParam == null) {
			ajaxSpiderParam = new AjaxSpiderParam();
		}
		return ajaxSpiderParam;
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
		if (getView() != null) {
			getSpiderPanel().startScan(node.getHierarchicNodeName(), inScope);
		}
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
	
	SpiderThread createSpiderThread(String url, boolean inScope, SpiderListener spiderListener) {
		SpiderThread spiderThread = new SpiderThread(url, this, inScope, spiderListener);
		spiderThread.addSpiderListener(getSpiderListener());
		
		return spiderThread;
	}
	
	private SpiderListener getSpiderListener() {
		if (spiderListener == null) {
			createSpiderListener();
		}
		return spiderListener;
	}

	private synchronized void createSpiderListener() {
		if (spiderListener == null) {
			spiderListener = new ExtensionAjaxSpiderListener();
		}
	}

	boolean isSpiderRunning() {
		return spiderRunning;
	}

	private void setSpiderRunning(boolean running) {
		spiderRunning = running;
	}

	/**
	 * shows the chrome alert
	 */
	public void showChromeAlert() {
		addDialog = new ChromeAlertDialog(getView().getMainFrame(), false, this);
		addDialog.setVisible(true);
	}
	
	private class SpiderSessionChangedListener implements SessionChangedListener {

		@Override
		public void sessionChanged(Session session) {
		}

		@Override
		public void sessionAboutToChange(Session session) {
			ajaxSpiderApi.reset();
		}

		@Override
		public void sessionScopeChanged(Session session) {
		}

		@Override
		public void sessionModeChanged(Mode mode) {
			if (getView() != null) {
				getSpiderPanel().sessionModeChanged(mode);
			}
		}
	}

	private class ExtensionAjaxSpiderListener implements SpiderListener {

		@Override
		public void spiderStarted() {
			setSpiderRunning(true);
		}

		@Override
		public void foundMessage(HistoryReference historyReference, HttpMessage httpMessage) {
		}

		@Override
		public void spiderStopped() {
			setSpiderRunning(false);
		}
	}
}