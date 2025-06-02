/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.revisit;

import java.util.List;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages.
 *
 * This class is defines the popup menu item.
 */
@SuppressWarnings("serial")
public class RightClickRevisitMenu extends PopupMenuItemSiteNodeContainer {

    private static final long serialVersionUID = 1L;
    private ExtensionRevisit extension = null;
    private boolean enable;

    /**
     * @param ext
     * @param label
     */
    public RightClickRevisitMenu(ExtensionRevisit ext, String label, boolean enable) {
        super(label);
        this.extension = ext;
        this.enable = enable;
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        return (invoker == Invoker.SITES_PANEL);
    }

    @Override
    public boolean isButtonEnabledForSiteNode(SiteNode sn) {
        return !sn.isRoot() && (extension.isEnabledForSite(sn) != this.enable);
    }

    @Override
    public void performHistoryReferenceActions(List<HistoryReference> hrefs) {
        super.performHistoryReferenceActions(hrefs);
    }

    @Override
    public void performAction(SiteNode sn) {
        if (enable) {
            extension.displayRevisitDialog(sn);
        } else {
            extension.unsetEnabledForSite(sn);
        }
    }
}
