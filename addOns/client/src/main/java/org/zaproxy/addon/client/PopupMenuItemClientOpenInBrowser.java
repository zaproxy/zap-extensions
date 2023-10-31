/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;

@SuppressWarnings("serial")
public class PopupMenuItemClientOpenInBrowser extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER =
            LogManager.getLogger(PopupMenuItemClientOpenInBrowser.class);
    private ProvidedBrowser browser;

    public PopupMenuItemClientOpenInBrowser(
            String label,
            ExtensionSelenium ext,
            ProvidedBrowser browser,
            ClientMapPanel clientMapPanel) {
        super(label);
        this.browser = browser;

        this.addActionListener(
                l -> {
                    new Thread(
                                    () -> {
                                        try {
                                            ext.getProxiedBrowser(
                                                    browser.getId(),
                                                    clientMapPanel
                                                            .getSelectedNode()
                                                            .getUserObject()
                                                            .getUrl());
                                        } catch (Exception e) {
                                            View.getSingleton().showWarningDialog(e.getMessage());
                                            LOGGER.error(e.getMessage(), e);
                                        }
                                    })
                            .start();
                });
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        if (browser == null || !browser.isConfigured()) {
            return false;
        }
        return super.isEnabled();
    }
}
