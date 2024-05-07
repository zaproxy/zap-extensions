/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

@SuppressWarnings("serial")
public class PopupMenuSpider extends PopupMenuItemSiteNodeContainer {

    private static final long serialVersionUID = 1L;
    private ExtensionClientIntegration extension = null;

    public PopupMenuSpider(String label, ExtensionClientIntegration extension) {
        super(label);
        this.setIcon(extension.getIcon());
        this.extension = extension;
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("attack.site.popup");
    }

    @Override
    public int getParentWeight() {
        return MenuWeights.MENU_ATTACK_WEIGHT;
    }

    @Override
    public int getWeight() {
        return MenuWeights.MENU_ATTACK_CLIENT_WEIGHT;
    }

    @Override
    public void performAction(SiteNode node) {
        if (node != null) {
            extension.showScanDialog(node);
        }
    }

    @Override
    public boolean isButtonEnabledForSiteNode(SiteNode node) {
        if (!node.isRoot()) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        switch (invoker) {
            case ALERTS_PANEL:
            case ACTIVE_SCANNER_PANEL:
            case FORCED_BROWSE_PANEL:
            case FUZZER_PANEL:
                return false;
            case HISTORY_PANEL:
            case SITES_PANEL:
            case SEARCH_PANEL:
            default:
                return true;
        }
    }
}
