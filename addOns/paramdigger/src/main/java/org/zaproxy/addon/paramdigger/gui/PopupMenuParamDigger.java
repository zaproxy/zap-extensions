/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger.gui;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.paramdigger.ExtensionParamDigger;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class PopupMenuParamDigger extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private ExtensionParamDigger extension;

    public PopupMenuParamDigger(ExtensionParamDigger ext, String label) {
        super(label);
        this.extension = ext;
        this.setIcon(ExtensionParamDigger.getIcon());
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
    public int getParentMenuIndex() {
        return ATTACK_MENU_INDEX;
    }

    @Override
    protected void performAction(HttpMessage httpMessage) {
        extension.showParamDiggerDialog(httpMessage);
    }
}
