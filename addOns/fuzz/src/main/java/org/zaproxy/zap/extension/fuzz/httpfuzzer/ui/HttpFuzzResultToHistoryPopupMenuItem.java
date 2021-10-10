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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class HttpFuzzResultToHistoryPopupMenuItem extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1692164709968649149L;

    public HttpFuzzResultToHistoryPopupMenuItem() {
        super(Constant.messages.getString("fuzz.panel.popup.add.site.history.label"), true);
    }

    @Override
    protected void performAction(HttpMessage httpMessage) {
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        extHistory.addHistory(httpMessage, HistoryReference.TYPE_ZAP_USER);
        HistoryReference currentHr = httpMessage.getHistoryRef();
        currentHr.addTag(Constant.messages.getString("fuzz.panel.popup.add.site.history.tag"));
        currentHr.setCustomIcon("org/zaproxy/zap/extension/fuzz/resources/icons/fuzzer.png", true);

        SiteMap currentTree = Model.getSingleton().getSession().getSiteTree();
        currentTree.addPath(currentHr);
    }

    @Override
    protected boolean isEnableForInvoker(
            Invoker invoker, HttpMessageContainer httpMessageContainer) {
        return invoker == Invoker.FUZZER_PANEL;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
