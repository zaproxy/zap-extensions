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
package org.zaproxy.addon.paramdigger.gui;

import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer;

@SuppressWarnings("serial")
public class ParamDiggerPopUpMenuNote extends PopupMenuItemHistoryReferenceContainer {
    private final ExtensionHistory ext;

    public ParamDiggerPopUpMenuNote(ExtensionHistory extensionHistory) {
        super("paramdigger.popup.note");
        this.ext = extensionHistory;
    }

    @Override
    public void performAction(HistoryReference href) {
        try {
            System.out.println("Performing action PARAM DIGGER NOTE");
            ext.showNotesAddDialog(href, href.getHttpMessage().getNote());
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
        }
    }

    @Override
    protected boolean isEnableForInvoker(
            Invoker invoker, HttpMessageContainer httpMessageContainer) {
        // TODO Auto-generated method stub
        return true;
    }
}
