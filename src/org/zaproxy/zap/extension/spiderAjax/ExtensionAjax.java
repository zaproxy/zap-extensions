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

import java.awt.Event;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * Main class of the plugin, it instantiates the rest of them.
 *  @author Guifre Ruiz Utges
 */
public class ExtensionAjax extends ExtensionAdaptor {

	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);
	public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
	public static final String NAME = "ExtensionSpiderAjax";

	private static final List<Class<?>> DEPENDENCIES;

	static {
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionSelenium.class);

		DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}

	private SpiderPanel spiderPanel = null;
	private PopupMenuAjaxSite popupMenuSpiderSite = null;
	private ZapMenuItem menuItemCustomScan;
	private AjaxSpiderDialog spiderDialog = null;
	private OptionsAjaxSpider optionsAjaxSpider = null;
	private List<String> excludeList = null;
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
        this.ajaxSpiderApi.addApiOptions(getAjaxSpiderParam());
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
			extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAjaxSite());
			extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());
			ExtensionHelp.enableHelpKey(getSpiderPanel(), "addon.spiderajax.tab");
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
            
            getView().getMainFrame().getMainFooterPanel().removeFooterToolbarRightLabel(getSpiderPanel().getScanStatus().getCountLabel());
        }
        
        API.getInstance().removeApiImplementor(ajaxSpiderApi);
        
        super.unload();
    }

    @Override
    public List<String> getActiveActions() {
        if (isSpiderRunning()) {
            List<String> activeActions = new ArrayList<>(1);
            activeActions.add(getMessages().getString("spiderajax.active.action"));
            return activeActions;
        }

        return super.getActiveActions();
    }

	@Override
	public List<Class<?>> getDependencies() {
		return DEPENDENCIES;
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
	 * @return the PopupMenuAjaxSite object
	 */
	private PopupMenuAjaxSite getPopupMenuAjaxSite() {
		if (popupMenuSpiderSite == null) {
			popupMenuSpiderSite = new PopupMenuAjaxSite(this.getMessages().getString("spiderajax.site.popup"), this);
		}
		return popupMenuSpiderSite;
	}

	private ZapMenuItem getMenuItemCustomScan() {
		if (menuItemCustomScan == null) {
			menuItemCustomScan = new ZapMenuItem(
					"spiderajax.menu.tools.label",
					KeyStroke.getKeyStroke(
							KeyEvent.VK_X,
							Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | Event.ALT_MASK,
							false));
			menuItemCustomScan.setEnabled(Control.getSingleton().getMode() != Mode.safe);

			menuItemCustomScan.addActionListener(new java.awt.event.ActionListener() {

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					showScanDialog(null);
				}
			});
		}
		return menuItemCustomScan;
	}

	/**
	 * 
	 * @return
	 */
	private OptionsAjaxSpider getOptionsSpiderPanel() {
		if (optionsAjaxSpider == null) {
			ExtensionSelenium extSelenium = Control.getSingleton()
					.getExtensionLoader()
					.getExtension(ExtensionSelenium.class);
			optionsAjaxSpider = new OptionsAjaxSpider(this.getMessages(), extSelenium.createBrowsersComboBoxModel());
		}
		return optionsAjaxSpider;
	}
	
	public void showScanDialog(SiteNode node) {
		if (spiderDialog == null) {
			spiderDialog = 
				new AjaxSpiderDialog(this, View.getSingleton().getMainFrame(), DisplayUtils.getScaledDimension(700, 500));
			spiderDialog.init(node);
		} else if (node != null) {
			spiderDialog.init(node);
		}
		
		spiderDialog.setVisible(true);
	}

	public void spiderSite(SiteNode node, boolean inScope, AjaxSpiderParam params) {
		if (getView() != null) {
			getSpiderPanel().startScan(node.getHistoryReference().getURI().toString(), inScope, params);
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
	
	SpiderThread createSpiderThread(String url, boolean inScope, SpiderListener spiderListener) throws URIException {
		return this.createSpiderThread(url, inScope, getAjaxSpiderParam(), spiderListener);
	}
	
	SpiderThread createSpiderThread(String url, boolean inScope, AjaxSpiderParam params, SpiderListener spiderListener) throws URIException {
		SpiderThread spiderThread = new SpiderThread(url, this, inScope, params, spiderListener);
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

	private class SpiderSessionChangedListener implements SessionChangedListener {

		@Override
		public void sessionChanged(Session session) {
		}

		@Override
		public void sessionAboutToChange(Session session) {
			ajaxSpiderApi.reset();
			if (getView() != null) {
				getSpiderPanel().reset();
			}
		}

		@Override
		public void sessionScopeChanged(Session session) {
		}

		@Override
		public void sessionModeChanged(Mode mode) {
			if (getView() != null) {
				getSpiderPanel().sessionModeChanged(mode);
				getMenuItemCustomScan().setEnabled(mode != Mode.safe);
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