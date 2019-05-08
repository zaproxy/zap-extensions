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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.FuzzerUIUtils;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class HttpFuzzAttackPopupMenuItem extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;

    private final ExtensionFuzz extensionFuzz;
    private final HttpFuzzerHandler fuzzerHandler;

    public HttpFuzzAttackPopupMenuItem(
            ExtensionFuzz extensionFuzz, HttpFuzzerHandler fuzzerHandler) {
        super(Constant.messages.getString("fuzz.httpfuzzer.popup.menu.item.attack"));
        setIcon(FuzzerUIUtils.FUZZER_ICON);

        this.extensionFuzz = extensionFuzz;
        this.fuzzerHandler = fuzzerHandler;
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
        HttpFuzzer fuzzer =
                fuzzerHandler.showFuzzerDialog(
                        httpMessage, extensionFuzz.getDefaultFuzzerOptions());
        if (fuzzer != null) {
            extensionFuzz.runFuzzer(fuzzerHandler, fuzzer);
        }
    }

    @Override
    protected boolean isEnableForInvoker(
            Invoker invoker, HttpMessageContainer httpMessageContainer) {
        if (!fuzzerHandler.canHandle(httpMessageContainer)) {
            return false;
        }
        switch (invoker) {
            case HISTORY_PANEL:
            case SITES_PANEL:
            case SEARCH_PANEL:
                return true;
            case ALERTS_PANEL:
            case ACTIVE_SCANNER_PANEL:
            case FORCED_BROWSE_PANEL:
            case FUZZER_PANEL:
            default:
                return false;
        }
    }
}
