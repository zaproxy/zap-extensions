/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.menu;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class ZestAddToScriptMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionZest extension;
    private ScriptNode parent;
    private String prefix = null;

    /** This method initializes */
    public ZestAddToScriptMenu(ExtensionZest extension) {
        super(Constant.messages.getString("zest.addto.new.title"), true);
        this.extension = extension;
        this.parent = null;
        this.setPrecedeWithSeparator(true);
    }

    public ZestAddToScriptMenu(ExtensionZest extension, ScriptNode parent) {
        super(parent.getNodeName(), true);
        this.extension = extension;
        this.parent = parent;
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.addto.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        extension.addToParent(parent, httpMessage, prefix);
    }

    @Override
    public void performActions(List<HttpMessage> messages) {
        // Work out common root??
        String prefix2 = null;
        String url = null;
        for (HttpMessage message : messages) {
            if (message == null) {
                continue;
            }
            url = message.getRequestHeader().getURI().toString();
            if (prefix2 == null) {
                // First one - select up to the last /
                prefix2 = url.substring(0, url.lastIndexOf("/"));
            } else if (!url.startsWith(prefix2)) {
                while (!url.startsWith(prefix2)) {
                    prefix2 = prefix2.substring(0, prefix2.length() - 2);
                }
            }
        }
        this.prefix = prefix2;
        super.performActions(messages);
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        View.getSingleton().getPopupList().remove(this);
    }
}
