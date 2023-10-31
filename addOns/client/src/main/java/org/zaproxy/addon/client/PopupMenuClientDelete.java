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

import java.awt.event.ActionEvent;
import javax.swing.JOptionPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;

public class PopupMenuClientDelete extends PopupMenuItemClient {

    private static final long serialVersionUID = 1L;

    public PopupMenuClientDelete(ClientMapPanel clientMapPanel) {
        super(Constant.messages.getString("client.tree.popup.delete"), clientMapPanel);
    }

    @Override
    public void performAction(ActionEvent e) {
        if (View.getSingleton()
                        .showConfirmDialog(
                                Constant.messages.getString("client.tree.popup.delete.confirm"))
                == JOptionPane.OK_OPTION) {
            getClientMapPanel().getExtension().deleteNodes(getClientMapPanel().getSelectedNodes());
        }
    }
}
