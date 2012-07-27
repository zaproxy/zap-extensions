package org.zaproxy.zap.extension.spiderAjax;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import javax.swing.ImageIcon;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.model.GenericScanner;

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
	private OptionsAjaxSpider optionsAjaxSpider = null;
	private List<String> excludeList = null;
	private ProxyAjax proxy = null;
	private ChromeAlertDialog addDialog = null;

	private ResourceBundle messages = null;

	/**
	 * initializes the extension
	 */
	public ExtensionAjax() {
		super(NAME);
		this.messages = ResourceBundle.getBundle(this.getClass().getPackage().getName()+ ".Messages", Constant.getLocale());
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
	 * @return void
	 */
	private void initialize() {
		this.setName(NAME);
	}

	/**
	 * starts the proxy and all elements of the UI
	 * @param extensionHook the extension
	 */
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		if (getView() != null) {
			@SuppressWarnings("unused")
			ExtensionHookView pv = extensionHook.getHookView();
			getSpiderPanel().setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
			extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());
			//extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpider());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpiderSite());
			ExtensionHelp.enableHelpKey(getSpiderPanel(), "ui.tabs.spider");
			extensionHook.getHookView().addStatusPanel(getSpiderPanel());

		}
	}

	/**
	 * Creates the panel with the config of the proxy
	 * @return the panel
	 */
	protected SpiderPanel getSpiderPanel() {
		if (spiderPanel == null) {
			spiderPanel = new SpiderPanel(this);
			spiderPanel.setName(this.getString("ajax.panel.title"));
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
	 * @return the PopupMenuAjaxSite object
	 */
	private PopupMenuAjaxSite getPopupMenuSpiderSite() {
		if (popupMenuSpiderSite == null) {
			popupMenuSpiderSite = new PopupMenuAjaxSite(this.getString("ajax.site.popup"), this);
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
	public void spiderSite(SiteNode node, boolean incPort) {
		this.getSpiderPanel().scanSite(node, incPort);
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
	 * @param key to retrieve
	 * @return the value of the key in messages
	 */
	public String getString(String key) {
		try {
			return messages.getString(key);
		} catch (MissingResourceException e) {
			logger.error(e);
			return  key;
		}
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
		return this.getString("ajax.desc");
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
	public void run(String url) {
		this.spiderPanel.newScanThread(url, this.getProxy().getAjaxProxyParam());
	}

	/**
	 * shows the chrome alert
	 */
	public void showBreakAddDialog() {
		addDialog = new ChromeAlertDialog(getView().getMainFrame(), false, this);
		addDialog.setVisible(true);
	}
	
}