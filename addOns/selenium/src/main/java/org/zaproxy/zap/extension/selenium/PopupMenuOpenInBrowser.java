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

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;

@SuppressWarnings("serial")
public class PopupMenuOpenInBrowser extends PopupMenuHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private ExtensionSelenium ext;

    public PopupMenuOpenInBrowser(ExtensionSelenium ext) {
        super(Constant.messages.getString("selenium.menu.openinbrowser"));
        this.ext = ext;
    }

    @Override
    public int getMenuIndex() {
        // This currently puts the menu just above the 'Open URL in System Browser' item
        return 7;
    }

    @Override
    protected boolean isButtonEnabledForNumberOfSelectedMessages(int numberOfSelectedMessages) {
        return true;
    }

    @Override
    public boolean isEnableForMessageContainer(MessageContainer<?> invoker) {
        // Recreate the sub menus
        removeAll();
        for (ProvidedBrowserUI bui : ext.getProvidedBrowserUIList()) {
            ProvidedBrowser pbrowser = bui.getBrowser();
            Browser browser = Browser.getBrowserWithId(bui.getBrowser().getId());
            if (!pbrowser.isHeadless()) {
                if (browser != null) {
                    add(new PopupMenuItemOpenInBrowser(bui.getName(), ext, bui.getBrowser()));
                }
            }
        }

        return super.isEnableForMessageContainer(invoker);
    }
}
