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
	 */
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		if (getView() != null) {
			@SuppressWarnings("unused")
			ExtensionHookView pv = extensionHook.getHookView();
		    pv.addStatusPanel(getSpiderPanel());
			getSpiderPanel().setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
			//extensionHook.getHookView().addStatusPanel(getSpiderPanel());

			extensionHook.getHookView().addOptionPanel(getOptionsSpiderPanel());

			//extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpider());
			extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuSpiderSite());
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
			spiderPanel = new SpiderPanel(this);
			spiderPanel.setName(this.getString("ajax.panel.title"));
			spiderPanel.setIcon(new ImageIcon(getClass().getResource("/resource/icon/16/spiderAjax.png")));
			}
		return spiderPanel;
	}

	/**
	 * 
	 * @return
	 */
	private PopupMenuAjax getPopupMenuSpider() {
		if (popupMenuSpider == null) {
			popupMenuSpider = new PopupMenuAjax(this);
			popupMenuSpider.setExtension(this);
		}
		return popupMenuSpider;
	}

	private PopupMenuAjaxSite getPopupMenuSpiderSite() {
		if (popupMenuSpiderSite == null) {
			popupMenuSpiderSite = new PopupMenuAjaxSite(this.getString("ajax.site.popup"), this);
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

	public boolean isScanning(SiteNode node, boolean incPort) {
		//return this.getSpiderPanel().isScanning(node, incPort);
		return true;
	}

	public void setExcludeList(List<String> ignoredRegexs) {
		this.excludeList = ignoredRegexs;
	}

	public List<String> getExcludeList() {
		return excludeList;
	}

	/**
	 * 
	 * @param key
	 * @return
	 */
	public String getString(String key) {
		try {
			return messages.getString(key);
		} catch (MissingResourceException e) {
			logger.error(e);
			return  key;
		}
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return this.getString("ajax.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			logger.error(e);
			return null;
		}
	}

	public void run(String url) {
		GenericScanner g = this.spiderPanel.newScanThread(url, this.getProxy().getAjaxProxyParam());
	}

	public void showBreakAddDialog() {
		addDialog = new ChromeAlertDialog(getView().getMainFrame(), false, this);
		addDialog.setVisible(true);
	}
	
}