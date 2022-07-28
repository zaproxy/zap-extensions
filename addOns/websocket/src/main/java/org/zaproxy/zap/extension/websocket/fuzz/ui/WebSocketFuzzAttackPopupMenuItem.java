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
package org.zaproxy.zap.extension.websocket.fuzz.ui;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.FuzzerUIUtils;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzer;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzerHandler;
import org.zaproxy.zap.extension.websocket.ui.httppanel.WebSocketMessageContainer;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuItemMessageContainer;

@SuppressWarnings("serial")
public class WebSocketFuzzAttackPopupMenuItem extends ExtensionPopupMenuItemMessageContainer {

    private static final long serialVersionUID = 3515657836446348454L;

    private final ExtensionFuzz extensionFuzz;
    private final WebSocketFuzzerHandler fuzzerHandler;

    private WebSocketMessageContainer websocketMessageContainer;

    public WebSocketFuzzAttackPopupMenuItem(
            ExtensionFuzz extensionFuzz, WebSocketFuzzerHandler fuzzerHandler) {
        super(Constant.messages.getString("websocket.fuzzer.popup.menu.item.attack"));
        setIcon(FuzzerUIUtils.FUZZER_ICON);

        this.extensionFuzz = extensionFuzz;
        this.fuzzerHandler = fuzzerHandler;

        addActionListener(
                e -> {
                    try {
                        performAction();
                    } finally {
                        resetState();
                    }
                });
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
    public boolean isEnableForMessageContainer(MessageContainer<?> messageContainer) {
        resetState();
        setEnabled(false);

        if (!(messageContainer instanceof WebSocketMessageContainer)) {
            return false;
        }

        if (!fuzzerHandler.canHandle(messageContainer)) {
            return false;
        }

        websocketMessageContainer = (WebSocketMessageContainer) messageContainer;

        setEnabled(true);
        return true;
    }

    private void performAction() {
        WebSocketFuzzer fuzzer =
                fuzzerHandler.showFuzzerDialog(
                        websocketMessageContainer, extensionFuzz.getDefaultFuzzerOptions());
        if (fuzzer != null) {
            extensionFuzz.runFuzzer(fuzzerHandler, fuzzer);
        }
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        super.dismissed(selectedMenuComponent);

        if (this != selectedMenuComponent) {
            resetState();
        }
    }

    private void resetState() {
        websocketMessageContainer = null;
    }
}
