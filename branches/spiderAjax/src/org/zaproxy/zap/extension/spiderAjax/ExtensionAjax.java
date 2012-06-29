/*
 * This is the main class of the plugin. It instantiates the rest of the classes. 
 *  
 */
package org.zaproxy.zap.extension.spiderAjax;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.model.GenericScanner;

public class ExtensionAjax extends ExtensionAdaptor {

	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);
	public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;
	public static final String NAME = "ExtensionSpiderAjax";

	private SpiderPanel spiderPanel = null;
	private PopupMenuSpider popupMenuSpider = null;
	private PopupMenuSpiderSite popupMenuSpiderSite = null;
	private OptionsAjaxSpider optionsAjaxSpider = null;
	private List<String> excludeList = null;
	private ProxyAjax proxy = null;

	/**
	 * initializes the extension
	 */
	public ExtensionAjax() {
		super();
		initialize();
	}

	/**
	 * @return the new ajax proxy
	 */
	public ProxyAjax getProxy() {
		return this.proxy;
	}

	/**
	 * @param name
	 */
	public ExtensionAjax(String name) {
		super(name);
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		this.setOrder(30);
		this.setName(NAME);
		// API.getInstance().registerApiImplementor(new SpiderAPI(this));
	}

	/**
	 * starts the proxy and all elements of the UI
	 */
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);
		this.proxy = new ProxyAjax();

		if (getView() != null) {
			@SuppressWarnings("unused")
			ExtensionHookView pv = extensionHook.getHookView();
			extensionHook.getHookView().addStatusPanel(getSpiderPanel());
			extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpider());
			// extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpiderSite());
			ExtensionHelp.enableHelpKey(getSpiderPanel(), "ui.tabs.spider");
		}
	}

	/**
	 * creates the panel with the config of the proxy
	 * 
	 * @return the panel
	 */
	protected SpiderPanel getSpiderPanel() {
		if (spiderPanel == null) {
			spiderPanel = new SpiderPanel(this, this.getProxy()
					.getSpiderParam());
		}
		return spiderPanel;
	}

	/**
	 * 
	 * @return
	 */
	private PopupMenuSpider getPopupMenuSpider() {
		if (popupMenuSpider == null) {
			popupMenuSpider = new PopupMenuSpider();
			popupMenuSpider.setExtension(this);
		}
		return popupMenuSpider;
	}

	private PopupMenuSpiderSite getPopupMenuSpiderSite() {
		if (popupMenuSpiderSite == null) {
			popupMenuSpiderSite = new PopupMenuSpiderSite(Constant.messages
					.getString("ajax.site.popup"), this);
			// popupMenuSpider.setExtensionSite(this);
		}
		return popupMenuSpiderSite;
	}

	private OptionsAjaxSpider getOptionsSpiderPanel() {
		if (optionsAjaxSpider == null) {
			optionsAjaxSpider = new OptionsAjaxSpider(this);
		}
		return optionsAjaxSpider;
	}

	public void spiderSite(SiteNode node, boolean incPort) {
		this.getSpiderPanel().scanSite(node, incPort);
	}

	public int getThreadPerScan() {
		// return this.getOptionsSpiderPanel().getThreads();
		return 1;
	}

	public boolean isScanning(SiteNode node, boolean incPort) {
		return this.getSpiderPanel().isScanning(node, incPort);
	}

	public void setExcludeList(List<String> ignoredRegexs) {
		this.excludeList = ignoredRegexs;
	}

	public List<String> getExcludeList() {
		return excludeList;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("ajax.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	public void run(String url) {
		GenericScanner g = this.spiderPanel.newScanThread(url, this.getProxy()
				.getSpiderParam());
	}

}