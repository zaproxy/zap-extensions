/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.brk;

import java.awt.Component;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.brk.BreakpointsPanel;
import org.zaproxy.zap.extension.brk.ExtensionBreak;

public class PopupMenuEditBreak extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private ExtensionBreak extension;

    public PopupMenuEditBreak() {
        super(Constant.messages.getString("brk.edit.popup"));
        initialize();
    }

    public void setExtension(ExtensionBreak extension) {
        this.extension = extension;
    }

    private void initialize() {
        this.addActionListener(
                new java.awt.event.ActionListener() {

                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        extension.editUiSelectedBreakpoint();
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker.getName() != null && invoker.getName().equals(BreakpointsPanel.PANEL_NAME)) {
            return true;
        }
        return false;
    }
}
