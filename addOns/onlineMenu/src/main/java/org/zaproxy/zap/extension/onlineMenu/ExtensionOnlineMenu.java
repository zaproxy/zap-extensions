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
package org.zaproxy.zap.extension.onlineMenu;

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.KeyStroke;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * A ZAP extension which adds the 'standard' top level online menu items. 
 * 
 * This class is defines the extension.
 */
public class ExtensionOnlineMenu extends ExtensionAdaptor {

    public static final String ZAP_HOMEPAGE				= "https://www.owasp.org/index.php/ZAP";
    public static final String ZAP_EXTENSIONS_PAGE		= "https://github.com/zaproxy/zap-extensions";
    public static final String ZAP_DOWNLOADS_PAGE		= "https://github.com/zaproxy/zaproxy/wiki/Downloads";
    public static final String ZAP_WIKI_PAGE			= "https://github.com/zaproxy/zaproxy/wiki";
    public static final String ZAP_FAQ_PAGE				= "https://github.com/zaproxy/zaproxy/wiki/FAQtoplevel";
    public static final String ZAP_NEWSLETTERS_PAGE		= "https://github.com/zaproxy/zaproxy/wiki/Newsletters";
    public static final String ZAP_USER_GROUP_PAGE		= "https://groups.google.com/group/zaproxy-users";
    public static final String ZAP_DEV_GROUP_PAGE		= "https://groups.google.com/group/zaproxy-develop";
    public static final String ZAP_ISSUES_PAGE			= "https://github.com/zaproxy/zaproxy/issues";

	// The name is public so that other extensions can access it
	public static final String NAME = "ExtensionOnlineMenu";
	
	private static final String PREFIX = "onlineMenu";

    public ExtensionOnlineMenu() {
        super(NAME);
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    if (getView() != null) {
			// Homepage
			@SuppressWarnings("deprecation")
			ZapMenuItem menuHomepage = new ZapMenuItem("onlineMenu.home",
					// TODO Use getMenuShortcutKeyMaskEx() (and remove warn suppression) when targeting Java 10+
					KeyStroke.getKeyStroke(KeyEvent.VK_Z, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask(), false));
			menuHomepage.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuHomepage.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_HOMEPAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuHomepage);

			// Extensions
			ZapMenuItem menuExtPage = new ZapMenuItem("onlineMenu.ext");
			menuExtPage.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuExtPage.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_EXTENSIONS_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuExtPage);

			// Wiki
			ZapMenuItem menuWiki = new ZapMenuItem("onlineMenu.wiki");
			menuWiki.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuWiki.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_WIKI_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuWiki);

			// FAQ
			ZapMenuItem menuFAQ = new ZapMenuItem("onlineMenu.faq");
			menuFAQ.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuFAQ.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_FAQ_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuFAQ);

			// Newsletters
			ZapMenuItem menuNews = new ZapMenuItem("onlineMenu.news");
			menuNews.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuNews.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_NEWSLETTERS_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuNews);

			// UserGroup
			ZapMenuItem menuUserGroup = new ZapMenuItem("onlineMenu.usergroup");
			menuUserGroup.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuUserGroup.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_USER_GROUP_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuUserGroup);

			// DevGroup
			ZapMenuItem menuDevGroup = new ZapMenuItem("onlineMenu.devgroup");
			menuDevGroup.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuDevGroup.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_DEV_GROUP_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuDevGroup);

			// Issues
			ZapMenuItem menuIssues = new ZapMenuItem("onlineMenu.issues");
			menuIssues.setEnabled(DesktopUtils.canOpenUrlInBrowser());
			menuIssues.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
					DesktopUtils.openUrlInBrowser(ZAP_ISSUES_PAGE);
				}
			});
			extensionHook.getHookMenu().addOnlineMenuItem(menuIssues);
	    }
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