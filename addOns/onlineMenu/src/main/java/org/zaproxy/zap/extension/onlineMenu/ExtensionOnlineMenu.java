/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.onlineMenu;

import java.awt.event.KeyEvent;
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

    public static final String ZAP_HOMEPAGE = "https://www.zaproxy.org/";
    public static final String ZAP_EXTENSIONS_PAGE = "https://www.zaproxy.org/addons/";
    public static final String ZAP_DOWNLOADS_PAGE = "https://www.zaproxy.org/download/";
    public static final String ZAP_FAQ_PAGE = "https://www.zaproxy.org/faq/";
    public static final String ZAP_VIDEOS_PAGE = "https://www.zaproxy.org/videos/";
    public static final String ZAP_USER_GROUP_PAGE =
            "https://groups.google.com/group/zaproxy-users";
    public static final String ZAP_DEV_GROUP_PAGE =
            "https://groups.google.com/group/zaproxy-develop";
    public static final String ZAP_ISSUES_PAGE = "https://github.com/zaproxy/zaproxy/issues";

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
            ZapMenuItem menuHomepage =
                    new ZapMenuItem(
                            "onlineMenu.home",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_Z, 0, false));
            menuHomepage.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuHomepage.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            DesktopUtils.openUrlInBrowser(ZAP_HOMEPAGE);
                        }
                    });
            extensionHook.getHookMenu().addOnlineMenuItem(menuHomepage);

            // Extensions
            ZapMenuItem menuExtPage = new ZapMenuItem("onlineMenu.ext");
            menuExtPage.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuExtPage.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            DesktopUtils.openUrlInBrowser(ZAP_EXTENSIONS_PAGE);
                        }
                    });
            extensionHook.getHookMenu().addOnlineMenuItem(menuExtPage);

            // FAQ
            ZapMenuItem menuFAQ = new ZapMenuItem("onlineMenu.faq");
            menuFAQ.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuFAQ.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            DesktopUtils.openUrlInBrowser(ZAP_FAQ_PAGE);
                        }
                    });
            extensionHook.getHookMenu().addOnlineMenuItem(menuFAQ);

            // Videos
            ZapMenuItem menuVideos = new ZapMenuItem("onlineMenu.videos");
            menuVideos.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuVideos.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            DesktopUtils.openUrlInBrowser(ZAP_VIDEOS_PAGE);
                        }
                    });
            extensionHook.getHookMenu().addOnlineMenuItem(menuVideos);

            // UserGroup
            ZapMenuItem menuUserGroup = new ZapMenuItem("onlineMenu.usergroup");
            menuUserGroup.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuUserGroup.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            DesktopUtils.openUrlInBrowser(ZAP_USER_GROUP_PAGE);
                        }
                    });
            extensionHook.getHookMenu().addOnlineMenuItem(menuUserGroup);

            // DevGroup
            ZapMenuItem menuDevGroup = new ZapMenuItem("onlineMenu.devgroup");
            menuDevGroup.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuDevGroup.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            DesktopUtils.openUrlInBrowser(ZAP_DEV_GROUP_PAGE);
                        }
                    });
            extensionHook.getHookMenu().addOnlineMenuItem(menuDevGroup);

            // Issues
            ZapMenuItem menuIssues = new ZapMenuItem("onlineMenu.issues");
            menuIssues.setEnabled(DesktopUtils.canOpenUrlInBrowser());
            menuIssues.addActionListener(
                    new java.awt.event.ActionListener() {
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
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
