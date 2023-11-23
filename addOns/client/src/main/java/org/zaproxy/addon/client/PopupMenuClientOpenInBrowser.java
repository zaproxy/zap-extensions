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

import java.awt.Component;
import java.util.List;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;

@SuppressWarnings("serial")
public class PopupMenuClientOpenInBrowser extends ExtensionPopupMenu {

    private static final long serialVersionUID = 1L;
    private ClientMapPanel clientMapPanel;
    private ExtensionSelenium extSelenium;

    public PopupMenuClientOpenInBrowser(ClientMapPanel clientMapPanel) {
        super(Constant.messages.getString("client.tree.popup.browser"));
        extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);

        this.clientMapPanel = clientMapPanel;
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTree) {
            JTree tree = (JTree) invoker;
            if (ClientMapPanel.CLIENT_TREE_NAME.equals(tree.getName())) {
                removeAll();
                for (ProvidedBrowserUI bui : extSelenium.getProvidedBrowserUIList()) {
                    ProvidedBrowser pbrowser = bui.getBrowser();
                    Browser browser = Browser.getBrowserWithId(bui.getBrowser().getId());
                    if (!pbrowser.isHeadless()) {
                        if (browser != null) {
                            add(
                                    new PopupMenuItemClientOpenInBrowser(
                                            bui.getName(),
                                            extSelenium,
                                            bui.getBrowser(),
                                            clientMapPanel));
                        }
                    }
                }
                List<ClientNode> nodes = clientMapPanel.getSelectedNodes();
                this.setEnabled(nodes.size() == 1 && !nodes.get(0).isRoot());
                return true;
            }
        }
        return false;
    }
}
