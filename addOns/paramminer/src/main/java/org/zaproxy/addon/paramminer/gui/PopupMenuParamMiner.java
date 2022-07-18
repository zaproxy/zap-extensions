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
package org.zaproxy.addon.paramminer.gui;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.paramminer.ExtensionParamMiner;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class PopupMenuParamMiner extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private ExtensionParamMiner extension;

    public PopupMenuParamMiner(ExtensionParamMiner ext, String label) {
        super(label);
        this.extension = ext;
    }

    // @Override
    // protected void performAction(SiteNode node) {
    //     extension.showParamMinerDialog(node);
    // }

    @Override
    protected void performAction(HttpMessage httpMessage) {
        // TODO Auto-generated method stub
        extension.showParamMinerDialog(httpMessage);
    }
}
