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
import java.util.function.Function;

@SuppressWarnings("serial")
public class PopupMenuClientDetailsCopy extends PopupMenuItemClientDetails {

    private static final long serialVersionUID = 1L;

    private Function<ClientSideComponent, String> function;

    public PopupMenuClientDetailsCopy(
            ClientDetailsPanel clientDetailsPanel,
            String text,
            Function<ClientSideComponent, String> function) {
        super(text, clientDetailsPanel);
        this.function = function;
    }

    @Override
    public void performAction(ActionEvent e) {
        StringBuilder sb = new StringBuilder();
        for (ClientSideComponent obj : getClientDetailsPanel().getSelectedRows()) {
            String val = this.function.apply(obj);
            if (val != null) {
                sb.append(val);
            }
            sb.append('\n');
        }
        ClientUtils.setClipboardContents(sb.toString());
    }
}
