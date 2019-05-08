/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class PopupMenuItemOpenInBrowser extends
        PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger
            .getLogger(PopupMenuItemOpenInBrowser.class);
    private ExtensionSelenium ext;
    private ProvidedBrowser browser;

    public PopupMenuItemOpenInBrowser(String label, ExtensionSelenium ext,
            ProvidedBrowser browser) {
        super(label);
        this.ext = ext;
        this.browser = browser;
    }

    @Override
    public boolean isEnabled() {
        if (browser == null || !browser.isConfigured()) {
            return false;
        }
        return super.isEnabled();
    }

    @Override
    public void performAction(final HttpMessage msg) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    ext.getProxiedBrowser(browser.getId(), msg
                            .getRequestHeader().getURI().toString());
                } catch (Exception e) {
                    View.getSingleton().showWarningDialog(e.getMessage());
                    LOGGER.error(e.getMessage(), e);
                }
            }
        }).start();
    }

}
