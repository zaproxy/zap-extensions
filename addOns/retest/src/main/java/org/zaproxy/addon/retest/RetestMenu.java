/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.retest;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

@SuppressWarnings("serial")
public class RetestMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;
    private ExtensionRetest extension;

    public RetestMenu(ExtensionRetest ext) {
        super(Constant.messages.getString("retest.menu.title"), true);
        this.extension = ext;
    }

    @Override
    public void performAction(Alert alert) {
        if (alert.getSource().equals(Alert.Source.ACTIVE)
                || alert.getSource().equals(Alert.Source.PASSIVE)) {
            extension.addAlertToDialog(alert);
        }
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
