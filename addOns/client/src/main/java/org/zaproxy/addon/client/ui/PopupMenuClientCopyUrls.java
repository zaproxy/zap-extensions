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
package org.zaproxy.addon.client.ui;

import java.awt.event.ActionEvent;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.client.ClientUtils;
import org.zaproxy.addon.client.internal.ClientNode;

public class PopupMenuClientCopyUrls extends PopupMenuItemClient {

    private static final long serialVersionUID = 1L;

    public PopupMenuClientCopyUrls(ClientMapPanel clientMapPanel) {
        super(Constant.messages.getString("client.tree.popup.copyurls"), clientMapPanel);
    }

    @Override
    public void performAction(ActionEvent e) {
        StringBuilder sb = new StringBuilder();
        for (ClientNode node : getClientMapPanel().getSelectedNodes()) {
            if (!node.isRoot()
                    && node.getUserObject() != null
                    && !node.getUserObject().isStorage()) {
                sb.append(node.getUserObject().getUrl());
                sb.append('\n');
            }
        }
        ClientUtils.setClipboardContents(sb.toString());
    }
}
